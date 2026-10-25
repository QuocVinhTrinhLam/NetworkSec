"""Authenticated server-rendered dashboard routes."""

from __future__ import annotations

import csv
import io
import math
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.config import Settings
from app.db import Database
from app.models import AttackScenario
from app.web.auth import csrf_token, require_user, validate_csrf, verify_password


def csv_safe_row(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Prevent spreadsheet formula execution for attacker-controlled cells."""
    safe: dict[str, Any] = {}
    for field in fields:
        value = row.get(field, "")
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
            value = "'" + value
        safe[field] = value
    return safe


def create_router(database: Database, settings: Settings, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    def context(request: Request, **values: Any) -> dict[str, Any]:
        return {
            "request": request,
            "app_name": settings.app_name,
            "csrf_token": csrf_token(request),
            "current_user": request.session.get("user"),
            **values,
        }

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "mode": "mock" if settings.mock_mode else "wazuh",
            "wazuh": database.get_state("wazuh_health") or "not-started",
        }

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        return templates.TemplateResponse(request, "login.html", context(request))

    @router.post("/login")
    async def login(
        request: Request,
        username: Annotated[str, Form(max_length=100)],
        password: Annotated[str, Form(max_length=1024)],
        csrf: Annotated[str, Form()],
    ) -> Response:
        validate_csrf(request, csrf)
        if username != settings.admin_username or not verify_password(
            password, settings.admin_password_hash
        ):
            return templates.TemplateResponse(
                request,
                "login.html",
                context(request, error="Invalid username or password"),
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        request.session.clear()
        request.session["user"] = username
        csrf_token(request)
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/logout")
    async def logout(
        request: Request,
        csrf: Annotated[str, Form()],
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        validate_csrf(request, csrf)
        request.session.clear()
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/")
    async def root(_user: Annotated[str, Depends(require_user)]) -> Response:
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        recent_alerts, _ = database.search_alerts(hours=24, page_size=6)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            context(
                request,
                stats=database.dashboard_stats(),
                recent_alerts=recent_alerts,
            ),
        )

    @router.get("/partials/dashboard", response_class=HTMLResponse)
    async def dashboard_partial(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        recent_alerts, _ = database.search_alerts(hours=24, page_size=6)
        return templates.TemplateResponse(
            request,
            "partials/dashboard_content.html",
            context(
                request,
                stats=database.dashboard_stats(),
                recent_alerts=recent_alerts,
            ),
        )

    def parse_hours(value: str) -> int | None:
        return None if value == "all" else max(1, min(int(value), 8760))

    @router.get("/alerts", response_class=HTMLResponse)
    async def alerts(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
        time_range: str = Query("24"),
        severity: str = Query("", max_length=20),
        device: str = Query("", max_length=255),
        rule_id: str = Query("", max_length=64),
        source_ip: str = Query("", max_length=64),
        search: str = Query("", max_length=200),
        page: int = Query(1, ge=1),
    ) -> Response:
        try:
            hours = parse_hours(time_range)
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid time range") from error
        rows, total = database.search_alerts(
            hours=hours,
            severity=severity,
            device=device,
            rule_id=rule_id,
            source_ip=source_ip,
            search=search,
            page=page,
        )
        filters = {
            "time_range": time_range,
            "severity": severity,
            "device": device,
            "rule_id": rule_id,
            "source_ip": source_ip,
            "search": search,
        }
        return templates.TemplateResponse(
            request,
            "alerts.html",
            context(
                request,
                alerts=rows,
                total=total,
                page=page,
                pages=max(1, math.ceil(total / 25)),
                filters=filters,
            ),
        )

    @router.get("/alerts/export.csv")
    async def export_alerts(
        _user: Annotated[str, Depends(require_user)],
        time_range: str = Query("24"),
        severity: str = Query("", max_length=20),
    ) -> Response:
        try:
            hours = parse_hours(time_range)
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid time range") from error
        rows, _ = database.search_alerts(hours=hours, severity=severity, page_size=5000)
        output = io.StringIO()
        fields = [
            "id",
            "timestamp",
            "severity",
            "device_name",
            "device_type",
            "source_ip",
            "dest_ip",
            "rule_id",
            "rule_description",
            "acknowledged",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_safe_row(row, fields) for row in rows)
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )

    @router.get("/alerts/{alert_id}", response_class=HTMLResponse)
    async def alert_detail(
        alert_id: str,
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        alert = database.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return templates.TemplateResponse(
            request, "alert_detail.html", context(request, alert=alert)
        )

    @router.post("/alerts/{alert_id}/ack")
    async def acknowledge_alert(
        alert_id: str,
        request: Request,
        csrf: Annotated[str, Form()],
        user: Annotated[str, Depends(require_user)],
    ) -> Response:
        validate_csrf(request, csrf)
        if not database.acknowledge(alert_id, user):
            raise HTTPException(status_code=404, detail="Alert not found")
        return RedirectResponse(f"/alerts/{alert_id}", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/devices", response_class=HTMLResponse)
    async def devices(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        return templates.TemplateResponse(
            request,
            "devices.html",
            context(
                request,
                devices=database.devices(settings.device_silent_minutes),
                silent_minutes=settings.device_silent_minutes,
            ),
        )

    @router.get("/scenarios", response_class=HTMLResponse)
    async def scenarios(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        return templates.TemplateResponse(
            request,
            "scenarios.html",
            context(request, scenarios=database.list_scenarios()),
        )

    @router.post("/scenarios")
    async def add_scenario(
        request: Request,
        csrf: Annotated[str, Form()],
        technique: Annotated[str, Form(max_length=255)],
        tool: Annotated[str, Form(max_length=255)],
        expected_rule: Annotated[str, Form(max_length=255)],
        detected: Annotated[bool, Form()] = False,
        detection_time_seconds: Annotated[float | None, Form(ge=0)] = None,
        notes: Annotated[str, Form(max_length=2000)] = "",
        _user: Annotated[str, Depends(require_user)] = "",
    ) -> Response:
        validate_csrf(request, csrf)
        database.add_scenario(
            AttackScenario(
                id=None,
                technique=technique,
                tool=tool,
                expected_rule=expected_rule,
                detected=detected,
                detection_time_seconds=detection_time_seconds,
                notes=notes,
            )
        )
        return RedirectResponse("/scenarios", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/scenarios/export.csv")
    async def export_scenarios(_user: Annotated[str, Depends(require_user)]) -> Response:
        rows = database.list_scenarios()
        output = io.StringIO()
        fields = [
            "id",
            "technique",
            "tool",
            "expected_rule",
            "detected",
            "detection_time_seconds",
            "notes",
            "tested_at",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_safe_row(row, fields) for row in rows)
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=attack-scenarios.csv"},
        )

    return router
