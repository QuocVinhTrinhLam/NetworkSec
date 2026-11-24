"""Coordinate idempotent writes across Loki and PostgreSQL."""

from __future__ import annotations

from starlette.concurrency import run_in_threadpool

from app.schemas.api import AlertRecord
from app.schemas.correlation import AggregatedAlert, OspfCorrelationSnapshot
from app.schemas.event import NormalizedEvent
from app.storage.base import AlertStateStorage, LogStorage


class StorageWriter:
    """Write searchable logs before publishing their aggregate state reference."""

    def __init__(self, logs: LogStorage, alerts: AlertStateStorage) -> None:
        self.logs = logs
        self.alerts = alerts

    async def persist(self, event: NormalizedEvent, alert: AggregatedAlert) -> AlertRecord:
        await self.logs.push_event(event)
        return await self.persist_alert_state(event, alert)

    async def persist_alert_state(
        self, event: NormalizedEvent, alert: AggregatedAlert
    ) -> AlertRecord:
        return await run_in_threadpool(self.alerts.upsert_alert, alert, event)

    async def reconcile_ospf(self, snapshot: OspfCorrelationSnapshot) -> None:
        await run_in_threadpool(self.alerts.apply_ospf_snapshot, snapshot)
