"""Authenticated server-rendered dashboard routes."""

from __future__ import annotations

import csv
import io
import math
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.db import Database
from app.models import AttackScenario
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.event import EventSeverity, EventType, EventVendor
from app.services.catalog import RulesCatalog
from app.storage.base import AlertQuery, AlertStateStorage, EventQuery, LogStorage, StorageError
from app.web.auth import csrf_token, require_user, validate_csrf, verify_password


def csv_safe_row(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Prevent spreadsheet formula execution for attacker-controlled cells."""
    safe: dict[str, Any] = {}
    for field in fields:
        value = row.get(field, "")
        if isinstance(value, str):
            visible = value.lstrip(" \t\r\n\v\f\ufeff\u200b")
            if visible.startswith(("=", "+", "-", "@")):
                value = "'" + value
        safe[field] = value
    return safe


def create_router(
    database: Database,
    settings: Settings,
    templates: Jinja2Templates,
    logs: LogStorage,
    alert_states: AlertStateStorage,
) -> APIRouter:
    router = APIRouter()
    catalog = RulesCatalog.from_file(settings.rules_catalog)
    operational = settings.dashboard_backend == "operational"

    def context(request: Request, **values: Any) -> dict[str, Any]:
        if operational:
            monitor_status = {
                "label": "Operational storage",
                "detail": "Loki events / PostgreSQL alerts",
                "tone": "online",
            }
        else:
            monitor_status = {
                "label": "Demo mode",
                "detail": "Simulated alert stream",
                "tone": "demo",
            }
        return {
            "request": request,
            "app_name": settings.app_name,
            "csrf_token": csrf_token(request),
            "current_user": request.session.get("user"),
            "monitor_status": monitor_status,
            "operational": operational,
            **values,
        }

    def time_window(value: str) -> tuple[datetime, datetime]:
        end = datetime.now(UTC)
        hours = parse_hours(value)
        start = datetime(1970, 1, 1, tzinfo=UTC) if hours is None else end - timedelta(hours=hours)
        return start, end

    def alert_view(alert: AlertRecord) -> dict[str, Any]:
        return {
            "id": alert.aggregate_id,
            "timestamp": alert.last_seen.isoformat(),
            "severity": alert.severity.value,
            "device_name": alert.device_name or "Unknown device",
            "device_type": "network device",
            "interface": alert.interface_name,
            "source_ip": None,
            "dest_ip": None,
            "username": None,
            "rule_id": alert.rule_id,
            "rule_description": alert.event_family.replace("_", " ").title(),
            "event_types": [item.value for item in alert.event_types],
            "event_type": ", ".join(item.value for item in alert.event_types),
            "event_count": alert.count,
            "count": alert.count,
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
            "status": alert.status.value,
            "acknowledged": alert.status is AlertLifecycleStatus.ACKNOWLEDGED,
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": (
                alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
            ),
            "raw_log": "Raw events are available from the normalized event view and Loki.",
            "mitre_id": None,
            "mitre_name": None,
            "use_case_id": None,
            "recommended_response": None,
        }

    async def operational_dashboard_data() -> tuple[
        dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]
    ]:
        start, end = time_window("24")
        stats = await run_in_threadpool(alert_states.dashboard_stats, start, end)
        alert_page = await run_in_threadpool(
            alert_states.query_alerts,
            AlertQuery(start=start, end=end, page=1, page_size=6),
        )
        event_page = await logs.query_events(EventQuery(start=start, end=end, limit=6))
        return (
            stats,
            [alert_view(item) for item in alert_page.items],
            [item.model_dump(mode="json") for item in event_page.items],
        )

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "mode": "operational" if operational else "mock",
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
        if operational:
            try:
                stats, recent_alerts, recent_events = await operational_dashboard_data()
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
        else:
            recent_alerts, _ = database.search_alerts(hours=24, page_size=6)
            stats = database.dashboard_stats()
            recent_events = []
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            context(
                request,
                stats=stats,
                recent_alerts=recent_alerts,
                recent_events=recent_events,
            ),
        )

    @router.get("/partials/dashboard", response_class=HTMLResponse)
    async def dashboard_partial(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        if operational:
            try:
                stats, recent_alerts, recent_events = await operational_dashboard_data()
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
        else:
            recent_alerts, _ = database.search_alerts(hours=24, page_size=6)
            stats = database.dashboard_stats()
            recent_events = []
        return templates.TemplateResponse(
            request,
            "partials/dashboard_content.html",
            context(
                request,
                stats=stats,
                recent_alerts=recent_alerts,
                recent_events=recent_events,
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
        event_type: str = Query("", max_length=64),
        alert_status: str = Query("", alias="status", max_length=32),
        page: int = Query(1, ge=1),
    ) -> Response:
        try:
            hours = parse_hours(time_range)
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid time range") from error
        if operational:
            try:
                severity_filter = EventSeverity(severity) if severity else None
                event_filter = EventType(event_type) if event_type else None
                status_filter = AlertLifecycleStatus(alert_status).value if alert_status else None
                start, end = time_window(time_range)
                result = await run_in_threadpool(
                    alert_states.query_alerts,
                    AlertQuery(
                        start=start,
                        end=end,
                        page=page,
                        page_size=25,
                        severity=severity_filter,
                        status=status_filter,
                        event_type=event_filter,
                        device_name=device or None,
                    ),
                )
                rows = [alert_view(item) for item in result.items]
                total = result.total
            except ValueError as error:
                raise HTTPException(status_code=422, detail="Invalid alert filter") from error
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
        else:
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
            "event_type": event_type,
            "status": alert_status,
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
        device: str = Query("", max_length=255),
        rule_id: str = Query("", max_length=64),
        source_ip: str = Query("", max_length=64),
        search: str = Query("", max_length=200),
    ) -> Response:
        try:
            hours = parse_hours(time_range)
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid time range") from error
        rows, _ = database.search_alerts(
            hours=hours,
            severity=severity,
            device=device,
            rule_id=rule_id,
            source_ip=source_ip,
            search=search,
            page_size=5000,
        )
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
        if operational:
            try:
                record = await run_in_threadpool(alert_states.get_alert, alert_id)
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
            alert = alert_view(record) if record else None
        else:
            alert = database.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        catalog_entry = catalog.get(str(alert.get("use_case_id") or "")) or catalog.match(
            str(alert.get("rule_id") or ""),
            [str(group) for group in alert.get("groups", [])],
        )
        if catalog_entry:
            alert = {
                **alert,
                "recommended_response": catalog_entry.recommended_response_for("vi"),
            }
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
        if operational:
            try:
                acknowledged = await run_in_threadpool(
                    alert_states.acknowledge, alert_id, user, None
                )
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
            if acknowledged is None:
                raise HTTPException(status_code=404, detail="Alert not found")
        elif not database.acknowledge(alert_id, user):
            raise HTTPException(status_code=404, detail="Alert not found")
        return RedirectResponse(f"/alerts/{alert_id}", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/events", response_class=HTMLResponse)
    async def events(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
        time_range: str = Query("24"),
        severity: str = Query("", max_length=20),
        device: str = Query("", max_length=255),
        event_type: str = Query("", max_length=64),
        vendor: str = Query("", max_length=64),
        cursor: str | None = Query(None, max_length=65536),
    ) -> Response:
        if not operational:
            return templates.TemplateResponse(
                request,
                "events.html",
                context(
                    request,
                    events=[],
                    next_cursor=None,
                    filters={
                        "time_range": time_range,
                        "severity": severity,
                        "device": device,
                        "event_type": event_type,
                        "vendor": vendor,
                    },
                ),
            )
        try:
            start, end = time_window(time_range)
            result = await logs.query_events(
                EventQuery(
                    start=start,
                    end=end,
                    limit=50,
                    cursor=cursor,
                    severity=EventSeverity(severity) if severity else None,
                    event_type=EventType(event_type) if event_type else None,
                    vendor=EventVendor(vendor) if vendor else None,
                    device_name=device or None,
                )
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid event filter") from error
        except StorageError as error:
            raise HTTPException(
                status_code=503, detail="Operational storage unavailable"
            ) from error
        return templates.TemplateResponse(
            request,
            "events.html",
            context(
                request,
                events=[item.model_dump(mode="json") for item in result.items],
                next_cursor=result.next_cursor,
                filters={
                    "time_range": time_range,
                    "severity": severity,
                    "device": device,
                    "event_type": event_type,
                    "vendor": vendor,
                },
            ),
        )

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
