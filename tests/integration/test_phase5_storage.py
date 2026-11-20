from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas.correlation import AggregatedAlert
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import AlertQuery, EventQuery
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage

pytestmark = [
    pytest.mark.storage_integration,
    pytest.mark.skipif(
        os.getenv("RUN_STORAGE_INTEGRATION") != "1",
        reason="set RUN_STORAGE_INTEGRATION=1 for live Loki/PostgreSQL tests",
    ),
]


@pytest.mark.asyncio
async def test_loki_and_postgres_round_trip() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    event = NormalizedEvent(
        timestamp=now,
        received_at=now,
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="phase5-integration-sw",
        interface_name="Gi0/1",
        interface_state="down",
        message="Phase 5 storage integration event",
        raw_message=f"phase5-integration-{now.isoformat()}",
        parser_name="phase5-integration",
    )
    aggregate = AggregatedAlert(
        aggregate_id=event.event_id,
        rule_id="interface-link-state",
        event_family="link_state",
        group_key={
            "device_name": "phase5-integration-sw",
            "interface_name": "Gi0/1",
            "event_family": "link_state",
        },
        device_name="phase5-integration-sw",
        interface_name="Gi0/1",
        event_types=(EventType.LINK_DOWN,),
        window_start=now,
        window_end=now + timedelta(minutes=1),
        count=1,
        first_seen=now,
        last_seen=now,
        severity=EventSeverity.HIGH,
        notification_cooldown_seconds=300,
    )
    postgres = PostgresAlertStorage(os.environ["POSTGRES_DSN"], Path("migrations/postgresql"))
    loki = LokiLogStorage(os.getenv("LOKI_URL", "http://127.0.0.1:3100"))

    postgres.migrate()
    await loki.push_event(event)
    stored_alert = postgres.upsert_alert(aggregate, event)
    event_page = await loki.query_events(
        EventQuery(
            start=now - timedelta(seconds=1),
            end=now + timedelta(minutes=1),
            limit=10,
            device_name="phase5-integration-sw",
        )
    )
    alert_page = postgres.query_alerts(
        AlertQuery(
            start=now - timedelta(seconds=1),
            end=now + timedelta(minutes=1),
            page=1,
            page_size=10,
            device_name="phase5-integration-sw",
        )
    )
    first_claim = postgres.claim_notifications(EventSeverity.HIGH, now + timedelta(minutes=2))
    later_event = NormalizedEvent(
        timestamp=now + timedelta(seconds=1),
        received_at=now + timedelta(seconds=1),
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="phase5-integration-sw",
        interface_name="Gi0/1",
        interface_state="down",
        message="Phase 5 storage integration follow-up event",
        raw_message=f"phase5-integration-follow-up-{now.isoformat()}",
        parser_name="phase5-integration",
    )
    updated_aggregate = aggregate.model_copy(
        update={"count": 2, "last_seen": now + timedelta(seconds=1)}
    )
    postgres.upsert_alert(updated_aggregate, later_event)
    second_claim = postgres.claim_notifications(
        EventSeverity.HIGH, now + timedelta(minutes=2, seconds=1)
    )
    postgres.save_telegram_message_id(aggregate.aggregate_id, 1234, 99)

    assert event.event_id in {item.event_id for item in event_page.items}
    assert stored_alert.aggregate_id == aggregate.aggregate_id
    assert alert_page.total >= 1
    assert aggregate.aggregate_id in {item.aggregate_id for item in first_claim}
    assert aggregate.aggregate_id not in {item.aggregate_id for item in second_claim}
    assert postgres.get_telegram_message_id(aggregate.aggregate_id, 1234) == 99
