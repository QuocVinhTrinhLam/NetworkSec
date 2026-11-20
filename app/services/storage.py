"""Coordinate idempotent Phase 5 writes across Loki and PostgreSQL."""

from __future__ import annotations

from starlette.concurrency import run_in_threadpool

from app.schemas.api import AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import NormalizedEvent
from app.storage.base import AlertStateStorage, LogStorage


class StorageWriter:
    """Write searchable logs before publishing their aggregate state reference."""

    def __init__(self, logs: LogStorage, alerts: AlertStateStorage) -> None:
        self.logs = logs
        self.alerts = alerts

    async def persist(self, event: NormalizedEvent, alert: AggregatedAlert) -> AlertRecord:
        await self.logs.push_event(event)
        return await run_in_threadpool(self.alerts.upsert_alert, alert, event)
