"""Authenticated server-rendered dashboard routes."""

from __future__ import annotations

import csv
import io
import math
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.db import Database
from app.models import AttackScenario
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.event import EventSeverity, EventType, EventVendor
from app.services.catalog import RulesCatalog
from app.storage.base import (
    AlertListMetadata,
    AlertPage,
    AlertQuery,
    AlertQueueSummary,
    AlertStateStorage,
    EventQuery,
    LogStorage,
    StorageError,
)
from app.web.auth import csrf_token, require_user, validate_csrf, verify_password

CSV_ALERT_LIMIT = 5000


class AlertFilters(BaseModel):
    time_range: str = "24"
    severity: str = Field("", max_length=20)
    device: str = Field("", max_length=255)
    rule_id: str = Field("", max_length=64)
    source_ip: str = Field("", max_length=64)
    search: str = Field("", max_length=200)
    event_type: str = Field("", max_length=64)
    status: str = Field("", max_length=32)
    page: int = Field(1, ge=1)


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

    def alert_view(alert: AlertRecord, metadata: AlertListMetadata) -> dict[str, Any]:
        adjacency = metadata.adjacency
        neighbor = " ↔ ".join(map(str, adjacency.router_ids)) if adjacency else None
        return {
            "id": alert.aggregate_id,
            "timestamp": alert.last_seen.isoformat(),
            "severity": alert.severity.value,
            "device_name": alert.device_name or ("Router IDs" if neighbor else "Unknown device"),
            "device_type": "network device",
            "interface": alert.interface_name,
            "source_ip": ", ".join(metadata.source_ips),
            "neighbor": neighbor,
            "ospf_area": str(adjacency.area) if adjacency else None,
            "link_id": adjacency.link_id if adjacency else None,
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
            "acknowledged": alert.acknowledged_at is not None
            or alert.status is AlertLifecycleStatus.ACKNOWLEDGED,
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": (
                alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
            ),
            "note": alert.note,
            "mitre_id": None,
            "mitre_name": None,
            "use_case_id": None,
            "recommended_response": None,
        }

    def queue_rows(result: AlertPage) -> list[dict[str, Any]]:
        return [
            alert_view(item, result.metadata.get(item.aggregate_id, AlertListMetadata()))
            for item in result.items
        ]

    async def operational_queue(filters: AlertFilters, page_size: int, page: int) -> AlertPage:
        start, end = time_window(filters.time_range)
        return await run_in_threadpool(
            alert_states.query_alerts,
            AlertQuery(
                start=start,
                end=end,
                page=page,
                page_size=page_size,
                severity=EventSeverity(filters.severity) if filters.severity else None,
                status=AlertLifecycleStatus(filters.status).value if filters.status else None,
                event_type=EventType(filters.event_type) if filters.event_type else None,
                device_name=filters.device or None,
                include_active_before_start=filters.time_range == "24",
                rule_id=filters.rule_id or None,
                source_ip=(
                    str(ip_address(ip_address(filters.source_ip).packed))
                    if filters.source_ip
                    else None
                ),
                search=filters.search.strip() or None,
            ),
        )

    async def operational_dashboard_data() -> tuple[AlertQueueSummary, list[dict[str, Any]]]:
        start, end = time_window("24")
        summary = await run_in_threadpool(alert_states.queue_summary, start, end)
        alert_page = await run_in_threadpool(
            alert_states.query_alerts,
            AlertQuery(start=start, end=end, page=1, page_size=6, include_active_before_start=True),
        )
        return summary, queue_rows(alert_page)

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
        csrf: Annotated[str, Form()] = "",
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
        _user: Annotated[str, Depends(require_user)],
        csrf: Annotated[str, Form()] = "",
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
        return templates.TemplateResponse(
            request, "dashboard.html", await dashboard_context(request)
        )

    @router.get("/partials/dashboard", response_class=HTMLResponse)
    async def dashboard_partial(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        return templates.TemplateResponse(
            request, "partials/dashboard_content.html", await dashboard_context(request)
        )

    async def dashboard_context(request: Request) -> dict[str, Any]:
        if operational:
            try:
                summary, recent_alerts = await operational_dashboard_data()
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
            return context(request, queue_summary=summary, recent_alerts=recent_alerts)
        recent_alerts, _ = database.search_alerts(hours=24, page_size=6)
        return context(
            request, stats=database.dashboard_stats(), recent_alerts=recent_alerts, recent_events=[]
        )

    def parse_hours(value: str) -> int | None:
        return None if value == "all" else max(1, min(int(value), 8760))

    @router.get("/alerts", response_class=HTMLResponse)
    async def alerts(
        request: Request,
        _user: Annotated[str, Depends(require_user)],
        filters: Annotated[AlertFilters, Query()],
    ) -> Response:
        try:
            if operational:
                result = await operational_queue(filters, 25, filters.page)
                rows = queue_rows(result)
                total = result.total
            else:
                rows, total = database.search_alerts(
                    hours=parse_hours(filters.time_range),
                    severity=filters.severity,
                    device=filters.device,
                    rule_id=filters.rule_id,
                    source_ip=filters.source_ip,
                    search=filters.search,
                    page=filters.page,
                )
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid alert filter") from error
        except StorageError as error:
            raise HTTPException(
                status_code=503, detail="Operational storage unavailable"
            ) from error
        filter_query = urlencode(
            {key: value for key, value in filters.model_dump(exclude={"page"}).items() if value}
        )
        return templates.TemplateResponse(
            request,
            "alerts.html",
            context(
                request,
                alerts=rows,
                total=total,
                page=filters.page,
                pages=max(1, math.ceil(total / 25)),
                filters=filters,
                filter_query=filter_query,
                event_types=tuple(EventType),
            ),
        )

    @router.get("/alerts/export.csv")
    async def export_alerts(
        _user: Annotated[str, Depends(require_user)],
        filters: Annotated[AlertFilters, Query()],
    ) -> Response:
        headers = {"Content-Disposition": "attachment; filename=alerts.csv"}
        try:
            if operational:
                result = await operational_queue(filters, CSV_ALERT_LIMIT, 1)
                rows = queue_rows(result)
                if result.total > len(rows):
                    headers["X-Export-Truncated"] = "true"
            else:
                rows, _ = database.search_alerts(
                    hours=parse_hours(filters.time_range),
                    severity=filters.severity,
                    device=filters.device,
                    rule_id=filters.rule_id,
                    source_ip=filters.source_ip,
                    search=filters.search,
                    page_size=CSV_ALERT_LIMIT,
                )
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Invalid alert filter") from error
        except StorageError as error:
            raise HTTPException(
                status_code=503, detail="Operational storage unavailable"
            ) from error
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
        if operational:
            fields.extend(
                [
                    "event_type",
                    "neighbor",
                    "ospf_area",
                    "status",
                    "first_seen",
                    "last_seen",
                    "acknowledged_by",
                    "acknowledged_at",
                ]
            )
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_safe_row(row, fields) for row in rows)
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers=headers,
        )

    @router.get("/alerts/{alert_id}", response_class=HTMLResponse)
    async def alert_detail(
        alert_id: str,
        request: Request,
        _user: Annotated[str, Depends(require_user)],
    ) -> Response:
        evidence = None
        if operational:
            try:
                evidence = await run_in_threadpool(alert_states.get_alert_evidence, alert_id)
            except StorageError as error:
                raise HTTPException(
                    status_code=503, detail="Operational storage unavailable"
                ) from error
            alert = (
                alert_view(
                    evidence.alert,
                    AlertListMetadata(
                        evidence.ospf.adjacency if evidence.ospf else None,
                        tuple(
                            sorted({ref.source_ip for ref in evidence.event_refs if ref.source_ip})
                        ),
                    ),
                )
                if evidence
                else None
            )
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
            request, "alert_detail.html", context(request, alert=alert, evidence=evidence)
        )

    @router.post("/alerts/{alert_id}/ack")
    async def acknowledge_alert(
        alert_id: str,
        request: Request,
        user: Annotated[str, Depends(require_user)],
        csrf: Annotated[str, Form()] = "",
        note: Annotated[str | None, Form(max_length=1000)] = None,
    ) -> Response:
        validate_csrf(request, csrf)
        if operational:
            try:
                acknowledged = await run_in_threadpool(
                    alert_states.acknowledge, alert_id, user, note or None
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

    @router.post("/alerts/{alert_id}/resolve")
    async def resolve_alert(
        alert_id: str,
        request: Request,
        user: Annotated[str, Depends(require_user)],
        csrf: Annotated[str, Form()] = "",
        note: Annotated[str | None, Form(max_length=1000)] = None,
    ) -> Response:
        validate_csrf(request, csrf)
        if not operational:
            raise HTTPException(status_code=404, detail="Alert not found")
        try:
            resolved = await run_in_threadpool(
                alert_states.update_status,
                alert_id,
                AlertLifecycleStatus.RESOLVED,
                user,
                note or None,
            )
        except StorageError as error:
            raise HTTPException(
                status_code=503, detail="Operational storage unavailable"
            ) from error
        if resolved is None:
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
        event_id: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None,
        event_at: datetime | None = None,
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
            if event_id is not None or event_at is not None:
                if event_id is None or event_at is None or event_at.utcoffset() is None:
                    raise ValueError("event_id and a timezone-aware event_at are required")
                start, end = event_at, event_at + timedelta(seconds=1)
            else:
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
                    event_id=event_id,
                )
            )
        except (ValueError, OverflowError) as error:
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
                next_cursor=result.next_cursor if event_id is None else None,
                evidence_event_id=event_id,
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
        technique: Annotated[str, Form(max_length=255)],
        tool: Annotated[str, Form(max_length=255)],
        expected_rule: Annotated[str, Form(max_length=255)],
        csrf: Annotated[str, Form()] = "",
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
