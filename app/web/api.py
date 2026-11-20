"""Authenticated JSON API for Loki events and PostgreSQL alert state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from starlette.concurrency import run_in_threadpool

from app.schemas.api import (
    AlertAcknowledgementRequest,
    AlertLifecycleStatus,
    AlertPageResponse,
    AlertRecord,
    AlertStatusUpdateRequest,
    EventPageResponse,
    StorageHealthResponse,
)
from app.schemas.event import EventSeverity, EventType, EventVendor
from app.storage.base import (
    AlertQuery,
    AlertStateStorage,
    EventQuery,
    InvalidCursorError,
    LogStorage,
    StorageError,
    StorageUnavailableError,
)
from app.web.auth import require_api_csrf, require_api_user

AlertId = Annotated[
    str,
    Path(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]


def create_api_router(logs: LogStorage, alerts: AlertStateStorage) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["storage-api"])

    @router.get("/storage/health", response_model=StorageHealthResponse)
    async def storage_health(
        _user: Annotated[str, Depends(require_api_user)],
    ) -> StorageHealthResponse:
        loki_ready = await logs.ready()
        postgres_ready = await run_in_threadpool(alerts.ready)
        return StorageHealthResponse(
            status="ok" if loki_ready and postgres_ready else "degraded",
            loki="ready" if loki_ready else "unavailable",
            postgres="ready" if postgres_ready else "unavailable",
        )

    @router.get("/events", response_model=EventPageResponse)
    async def query_events(
        _user: Annotated[str, Depends(require_api_user)],
        start: Annotated[datetime | None, Query()] = None,
        end: Annotated[datetime | None, Query()] = None,
        severity: Annotated[EventSeverity | None, Query()] = None,
        event_type: Annotated[EventType | None, Query()] = None,
        vendor: Annotated[EventVendor | None, Query()] = None,
        device_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
        interface_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
        page_size: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(min_length=1, max_length=65536)] = None,
    ) -> EventPageResponse:
        range_start, range_end = _time_range(start, end)
        try:
            page = await logs.query_events(
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
                )
            )
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="Loki is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Loki query failed") from exc
        return EventPageResponse(
            items=page.items,
            page_size=page_size,
            next_cursor=page.next_cursor,
        )

    @router.get("/alerts", response_model=AlertPageResponse)
    def query_alerts(
        _user: Annotated[str, Depends(require_api_user)],
        start: Annotated[datetime | None, Query()] = None,
        end: Annotated[datetime | None, Query()] = None,
        severity: Annotated[EventSeverity | None, Query()] = None,
        alert_status: Annotated[AlertLifecycleStatus | None, Query(alias="status")] = None,
        event_type: Annotated[EventType | None, Query()] = None,
        device_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
        interface_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> AlertPageResponse:
        range_start, range_end = _time_range(start, end)
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

    @router.get("/alerts/{alert_id}", response_model=AlertRecord)
    def get_alert(
        alert_id: AlertId,
        _user: Annotated[str, Depends(require_api_user)],
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

    @router.post("/alerts/{alert_id}/acknowledge", response_model=AlertRecord)
    def acknowledge_alert(
        alert_id: AlertId,
        body: AlertAcknowledgementRequest,
        user: Annotated[str, Depends(require_api_user)],
        _csrf: Annotated[None, Depends(require_api_csrf)],
    ) -> AlertRecord:
        try:
            record = alerts.acknowledge(alert_id, user, body.note)
        except StorageUnavailableError as exc:
            raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
        except StorageError as exc:
            raise HTTPException(status_code=502, detail="Alert acknowledgement failed") from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return record

    @router.patch("/alerts/{alert_id}/status", response_model=AlertRecord)
    def update_alert_status(
        alert_id: AlertId,
        body: AlertStatusUpdateRequest,
        user: Annotated[str, Depends(require_api_user)],
        _csrf: Annotated[None, Depends(require_api_csrf)],
    ) -> AlertRecord:
        try:
            record = alerts.update_status(alert_id, body.status.value, user, body.note)
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
    range_start = start or range_end - timedelta(hours=24)
    if any(value.tzinfo is None or value.utcoffset() is None for value in (range_start, range_end)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="start and end must include a timezone",
        )
    range_start = range_start.astimezone(UTC)
    range_end = range_end.astimezone(UTC)
    if range_start >= range_end:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="start must be earlier than end",
        )
    return range_start, range_end
