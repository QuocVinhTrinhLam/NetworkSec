"""Authenticated JSON API for Loki events and PostgreSQL alert state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.schemas.api import (
    AlertAcknowledgementRequest,
    AlertEventEvidence,
    AlertEvidenceResponse,
    AlertHistoryEntry,
    AlertLifecycleStatus,
    AlertPageResponse,
    AlertRecord,
    AlertStatusUpdateRequest,
    ErrorResponse,
    EventPageResponse,
    OspfEvidenceSummary,
    StorageHealthResponse,
    ValidationErrorResponse,
)
from app.schemas.backend import Category, IndexedEvent, Page, Principal, Role
from app.schemas.event import EventSeverity, EventType, EventVendor
from app.services.backend import EventFilters, date_range, redact
from app.storage.backend import PostgresBackendStorage
from app.storage.base import (
    AlertQuery,
    AlertStateStorage,
    EventQuery,
    InvalidCursorError,
    LogStorage,
    StorageError,
    StorageUnavailableError,
)
from app.web.accounts import mutation_csrf, principal, roles

AlertId = Annotated[
    str,
    Path(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
Analyst = Annotated[Principal, Depends(roles(Role.ADMIN, Role.ANALYST))]
Reader = Annotated[Principal, Depends(principal)]
API_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "Authentication required"},
    403: {"model": ErrorResponse, "description": "Permission denied or invalid CSRF token"},
    422: {"model": ValidationErrorResponse, "description": "Invalid request"},
    502: {"model": ErrorResponse, "description": "Dependency operation failed"},
    503: {"model": ErrorResponse, "description": "Dependency is unavailable"},
}
NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "Resource not found"}
}
BODY_ERRORS: dict[int | str, dict[str, Any]] = {
    413: {"model": ErrorResponse, "description": "Request body too large"}
}


def create_api_router(logs: LogStorage, alerts: AlertStateStorage) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["storage-api"], responses=API_ERRORS)

    @router.get("/storage/health", response_model=StorageHealthResponse)
    async def storage_health(
        _user: Reader,
    ) -> StorageHealthResponse:
        loki_ready = await logs.ready()
        postgres_ready = await run_in_threadpool(alerts.ready)
        return StorageHealthResponse(
            status="ok" if loki_ready and postgres_ready else "degraded",
            loki="ready" if loki_ready else "unavailable",
            postgres="ready" if postgres_ready else "unavailable",
        )

    @router.get(
        "/events",
        response_model=EventPageResponse | Page[IndexedEvent],
        responses={400: {"model": ErrorResponse, "description": "Invalid cursor"}},
    )
    async def query_events(
        request: Request,
        _user: Analyst,
        start: Annotated[datetime | None, Query()] = None,
        end: Annotated[datetime | None, Query()] = None,
        severity: Annotated[EventSeverity | None, Query()] = None,
        event_type: Annotated[EventType | None, Query()] = None,
        vendor: Annotated[EventVendor | None, Query()] = None,
        device_name: Annotated[
            str | None, Query(min_length=1, max_length=255, pattern=r"^[^\x00]+$")
        ] = None,
        interface_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
        page_size: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(min_length=1, max_length=65536)] = None,
        include_ospf: Annotated[
            bool, Query(description="Include schema 1.1 OSPF events alongside legacy 1.0 events")
        ] = False,
        view: Literal["legacy", "catalog"] = "legacy",
        page: Annotated[int, Query(ge=1, le=1000)] = 1,
        sort: Literal["desc", "asc"] = "desc",
        device_id: UUID | None = None,
        category: Category | None = None,
        search: Annotated[
            str | None, Query(min_length=1, max_length=255, pattern=r"^[^\x00]+$")
        ] = None,
    ) -> JSONResponse | Page[IndexedEvent]:
        if (
            view == "catalog"
            or device_id is not None
            or category
            or search
            or sort == "asc"
            or page > 1
        ):
            storage: PostgresBackendStorage | None = request.app.state.backend
            if storage is None:
                raise StorageUnavailableError("PostgreSQL is unavailable")
            if cursor is not None or interface_name is not None:
                raise HTTPException(
                    422, "Catalog pagination uses page and does not accept interface_name"
                )
            if page_size > 200:
                raise HTTPException(422, "Catalog page_size must be at most 200")
            try:
                indexed_start, indexed_end = date_range(start, end)
            except (ValueError, OverflowError) as exc:
                raise HTTPException(
                    422, "Invalid time range. Use explicit offsets and at most 90 days."
                ) from exc
            filters = EventFilters(
                indexed_start,
                indexed_end,
                device_id,
                device_name,
                severity,
                category,
                event_type,
                vendor,
                search,
            )
            return await run_in_threadpool(storage.events, filters, page, page_size, sort)
        range_start, range_end = _time_range(start, end)
        try:
            loki_page = await logs.query_events(
                EventQuery(
                    start=range_start,
                    end=range_end,
                    limit=page_size,
                    cursor=cursor,
                    severity=severity,
                    event_type=event_type,
                    vendor=vendor,
                    device_name=device_name,
                    interface_name=interface_name,
                    schema_version=None if include_ospf else "1.0",
                )
            )
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="Loki is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Loki query failed") from exc
        page_data = EventPageResponse(
            items=loki_page.items,
            page_size=page_size,
            next_cursor=loki_page.next_cursor,
        ).model_dump(mode="json")
        # Sanitizing before model validation would derive a different event ID.
        for item in page_data["items"]:
            item["message"] = redact(item["message"])
            item["raw_message"] = "[restricted]"
        return JSONResponse(page_data)

    @router.get("/alerts", response_model=AlertPageResponse)
    def query_alerts(
        _user: Analyst,
        start: Annotated[datetime | None, Query()] = None,
        end: Annotated[datetime | None, Query()] = None,
        severity: Annotated[EventSeverity | None, Query()] = None,
        alert_status: Annotated[AlertLifecycleStatus | None, Query(alias="status")] = None,
        event_type: Annotated[EventType | None, Query()] = None,
        device_name: Annotated[
            str | None, Query(min_length=1, max_length=255, pattern=r"^[^\x00]+$")
        ] = None,
        interface_name: Annotated[
            str | None, Query(min_length=1, max_length=255, pattern=r"^[^\x00]+$")
        ] = None,
        page: Annotated[int, Query(ge=1, le=1000)] = 1,
        page_size: Annotated[int, Query(ge=1, le=200)] = 50,
        rule_id: Annotated[
            str | None, Query(min_length=1, max_length=128, pattern=r"^[^\x00]+$")
        ] = None,
        source_ip: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
        search: Annotated[
            str | None, Query(min_length=1, max_length=200, pattern=r"^[^\x00]+$")
        ] = None,
    ) -> AlertPageResponse:
        range_start, range_end = _time_range(start, end)
        try:
            address = (
                str(ip_address(ip_address(source_ip).packed)) if source_ip is not None else None
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid source IP address") from exc
        try:
            result = alerts.query_alerts(
                AlertQuery(
                    start=range_start,
                    end=range_end,
                    page=page,
                    page_size=page_size,
                    severity=severity,
                    status=alert_status.value if alert_status else None,
                    event_type=event_type,
                    device_name=device_name,
                    interface_name=interface_name,
                    include_active_before_start=start is None and end is None,
                    rule_id=rule_id,
                    source_ip=address,
                    search=search,
                )
            )
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert query failed") from exc
        return AlertPageResponse(
            items=result.items,
            total=result.total,
            page=page,
            page_size=page_size,
        )

    @router.get("/alerts/{alert_id}", response_model=AlertRecord, responses={**NOT_FOUND})
    def get_alert(
        alert_id: AlertId,
        _user: Analyst,
    ) -> AlertRecord:
        try:
            record = alerts.get_alert(alert_id)
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert query failed") from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return record

    @router.get(
        "/alerts/{alert_id}/evidence",
        response_model=AlertEvidenceResponse,
        responses={**NOT_FOUND},
    )
    def get_alert_evidence(
        alert_id: AlertId,
        _user: Analyst,
    ) -> AlertEvidenceResponse:
        try:
            result = alerts.get_alert_evidence(alert_id)
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert evidence query failed") from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return AlertEvidenceResponse(
            alert_id=alert_id,
            event_refs=tuple(AlertEventEvidence.model_validate(item) for item in result.event_refs),
            history=tuple(AlertHistoryEntry.model_validate(item) for item in result.history),
            ospf=OspfEvidenceSummary.model_validate(result.ospf) if result.ospf else None,
        )

    @router.post(
        "/alerts/{alert_id}/acknowledge",
        response_model=AlertRecord,
        responses={**NOT_FOUND, **BODY_ERRORS},
    )
    def acknowledge_alert(
        alert_id: AlertId,
        body: AlertAcknowledgementRequest,
        user: Analyst,
        _csrf: Annotated[None, Depends(mutation_csrf)],
    ) -> AlertRecord:
        try:
            record = alerts.acknowledge(alert_id, user.username, body.note)
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert acknowledgement failed") from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return record

    @router.patch(
        "/alerts/{alert_id}/status",
        response_model=AlertRecord,
        responses={**NOT_FOUND, **BODY_ERRORS},
    )
    def update_alert_status(
        alert_id: AlertId,
        body: AlertStatusUpdateRequest,
        user: Analyst,
        _csrf: Annotated[None, Depends(mutation_csrf)],
    ) -> AlertRecord:
        if user.role is Role.ANALYST and body.status is AlertLifecycleStatus.NEW:
            raise HTTPException(403, "Permission denied")
        try:
            record = alerts.update_status(alert_id, body.status.value, user.username, body.note)
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert status update failed") from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return record

    return router


def _time_range(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    range_end = end or datetime.now(UTC)
    try:
        range_start = start or range_end - timedelta(hours=24)
    except OverflowError as exc:
        raise HTTPException(422, "Invalid time range") from exc
    if any(value.tzinfo is None or value.utcoffset() is None for value in (range_start, range_end)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="start and end must include a timezone",
        )
    try:
        range_start = range_start.astimezone(UTC)
        range_end = range_end.astimezone(UTC)
    except OverflowError as exc:
        raise HTTPException(422, "Invalid time range") from exc
    if range_start >= range_end:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="start must be earlier than end",
        )
    return range_start, range_end
