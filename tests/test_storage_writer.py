from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.schemas.api import AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.services.storage import StorageWriter
from app.storage.base import AlertPage, AlertQuery, EventPage, EventQuery

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=NOW,
        received_at=NOW,
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="sw-01",
        interface_name="Gi0/1",
        message="link down",
        raw_message="link down raw",
        parser_name="storage-writer-test",
    )


def _aggregate(event: NormalizedEvent) -> AggregatedAlert:
    return AggregatedAlert(
        aggregate_id=event.event_id,
        rule_id="interface-link-state",
        event_family="link_state",
        group_key={"device_name": "sw-01", "interface_name": "Gi0/1"},
        device_name="sw-01",
        interface_name="Gi0/1",
        event_types=(EventType.LINK_DOWN,),
        window_start=NOW,
        window_end=NOW + timedelta(minutes=1),
        count=1,
        first_seen=NOW,
        last_seen=NOW,
        severity=EventSeverity.HIGH,
        notification_cooldown_seconds=300,
    )


class OrderedLogs:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def push_event(self, event: NormalizedEvent) -> None:
        self.calls.append(f"loki:{event.event_id}")

    async def query_events(self, query: EventQuery) -> EventPage:
        return EventPage((), None)

    async def ready(self) -> bool:
        return True


class OrderedAlerts:
    def __init__(self, calls: list[str], record: AlertRecord) -> None:
        self.calls = calls
        self.record = record

    def migrate(self) -> None:
        return None

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        self.calls.append(f"postgres:{event.event_id}")
        return self.record

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        return AlertPage((), 0)

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        return None

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        return None

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        return None

    def ready(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_storage_writer_publishes_log_before_alert_reference() -> None:
    event = _event()
    aggregate = _aggregate(event)
    record = AlertRecord(
        aggregate_id=aggregate.aggregate_id,
        rule_id=aggregate.rule_id,
        event_family=aggregate.event_family,
        device_name=aggregate.device_name,
        interface_name=aggregate.interface_name,
        event_types=aggregate.event_types,
        window_start=aggregate.window_start,
        window_end=aggregate.window_end,
        count=aggregate.count,
        first_seen=aggregate.first_seen,
        last_seen=aggregate.last_seen,
        severity=aggregate.severity,
        status="new",
        status_changed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )
    calls: list[str] = []

    result = await StorageWriter(OrderedLogs(calls), OrderedAlerts(calls, record)).persist(
        event, aggregate
    )

    assert result == record
    assert calls == [f"loki:{event.event_id}", f"postgres:{event.event_id}"]
