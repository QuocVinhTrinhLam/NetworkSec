"""Deterministic Phase 4 correlation and notification cooldown tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas.correlation import CorrelationConfig, CorrelationRule
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.services.correlation import CorrelationEngine, CorrelationStore, load_correlation_config

BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _config(*, window_seconds: int = 60, cooldown_seconds: int = 300) -> CorrelationConfig:
    return CorrelationConfig(
        rules=(
            CorrelationRule(
                id="interface-link-state",
                event_family="link_state",
                event_types=(EventType.LINK_UP, EventType.LINK_DOWN),
                group_by=("device_name", "interface_name", "event_family"),
                required_fields=("device_name", "interface_name"),
                window_seconds=window_seconds,
                notification_cooldown_seconds=cooldown_seconds,
            ),
        )
    )


def _event(
    sequence: int,
    timestamp: datetime,
    *,
    event_type: EventType = EventType.LINK_DOWN,
    device_name: str = "core-sw-01",
    interface_name: str = "GigabitEthernet0/1",
) -> NormalizedEvent:
    state = "up" if event_type is EventType.LINK_UP else "down"
    severity = EventSeverity.LOW if state == "up" else EventSeverity.HIGH
    return NormalizedEvent(
        timestamp=timestamp,
        received_at=timestamp + timedelta(milliseconds=100),
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=event_type,
        severity=severity,
        outcome=EventOutcome.UNKNOWN,
        device_name=device_name,
        message=f"Interface {interface_name}, changed state to {state}",
        raw_message=(
            f"<189>1 {timestamp.isoformat()} {device_name} IOS 42 LINK "
            f'[sequence@32473 id="{sequence}"] Interface {interface_name} {state}'
        ),
        interface_name=interface_name,
        interface_state=state,
        parser_name="phase4-test-fixture",
    )


def _engine(path: Path, config: CorrelationConfig | None = None) -> CorrelationEngine:
    store = CorrelationStore(path)
    store.initialize()
    return CorrelationEngine(store, config or _config())


def test_acceptance_100_link_events_create_one_traceable_alert(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "acceptance.db")
    event_ids: set[str] = set()
    aggregate_id = ""

    for sequence in range(1, 101):
        event = _event(
            sequence,
            BASE_TIME + timedelta(milliseconds=500 * (sequence - 1)),
            event_type=EventType.LINK_UP if sequence % 2 == 0 else EventType.LINK_DOWN,
        )
        event_ids.add(event.event_id)
        result = engine.process(event)
        assert result.matched is True
        assert result.duplicate is False
        assert result.alert is not None
        aggregate_id = result.alert.aggregate_id

    alerts = engine.store.list_alerts()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.aggregate_id == aggregate_id
    assert alert.count == 100
    assert alert.first_seen == BASE_TIME
    assert alert.last_seen == BASE_TIME + timedelta(seconds=49, milliseconds=500)
    assert alert.severity is EventSeverity.HIGH
    assert set(alert.event_types) == {EventType.LINK_UP, EventType.LINK_DOWN}

    traces = engine.store.trace_events(aggregate_id)
    assert len(traces) == 100
    assert {trace.event_id for trace in traces} == event_ids
    assert all(trace.raw_message == trace.event.raw_message for trace in traces)

    sent_to_telegram: list[str] = []
    first_claim = engine.store.claim_notification(aggregate_id, BASE_TIME + timedelta(seconds=60))
    if first_claim.allowed:
        sent_to_telegram.append(aggregate_id)
    duplicate_claim = engine.store.claim_notification(
        aggregate_id, BASE_TIME + timedelta(seconds=61)
    )
    if duplicate_claim.allowed:
        sent_to_telegram.append(aggregate_id)

    assert sent_to_telegram == [aggregate_id]
    assert duplicate_claim.allowed is False
    assert duplicate_claim.next_allowed_at == BASE_TIME + timedelta(seconds=360)


def test_fixed_window_end_is_exclusive(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "boundaries.db")

    before_end = engine.process(_event(1, BASE_TIME + timedelta(seconds=59, milliseconds=999)))
    at_end = engine.process(_event(2, BASE_TIME + timedelta(seconds=60)))

    assert before_end.alert is not None
    assert at_end.alert is not None
    assert before_end.alert.aggregate_id != at_end.alert.aggregate_id
    assert [alert.count for alert in engine.store.list_alerts()] == [1, 1]


def test_duplicate_delivery_is_idempotent(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "duplicate.db")
    event = _event(1, BASE_TIME + timedelta(seconds=5))

    first = engine.process(event)
    duplicate = engine.process(event)

    assert first.alert is not None
    assert duplicate.alert is not None
    assert duplicate.duplicate is True
    assert duplicate.alert.count == 1
    assert len(engine.store.trace_events(first.alert.aggregate_id)) == 1


def test_out_of_order_events_update_bounds_and_severity(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "out-of-order.db")

    later = engine.process(
        _event(2, BASE_TIME + timedelta(seconds=50), event_type=EventType.LINK_UP)
    )
    earlier = engine.process(
        _event(1, BASE_TIME + timedelta(seconds=10), event_type=EventType.LINK_DOWN)
    )

    assert later.alert is not None
    assert earlier.alert is not None
    assert earlier.alert.aggregate_id == later.alert.aggregate_id
    assert earlier.alert.count == 2
    assert earlier.alert.first_seen == BASE_TIME + timedelta(seconds=10)
    assert earlier.alert.last_seen == BASE_TIME + timedelta(seconds=50)
    assert earlier.alert.severity is EventSeverity.HIGH


def test_restart_preserves_count_dedup_and_notification_cooldown(tmp_path: Path) -> None:
    database_path = tmp_path / "restart.db"
    first_engine = _engine(database_path)
    first_event = _event(1, BASE_TIME + timedelta(seconds=10))
    first_result = first_engine.process(first_event)
    assert first_result.alert is not None
    aggregate_id = first_result.alert.aggregate_id
    assert first_engine.store.claim_notification(
        aggregate_id, BASE_TIME + timedelta(seconds=20)
    ).allowed

    restarted_engine = _engine(database_path)
    duplicate = restarted_engine.process(first_event)
    second = restarted_engine.process(
        _event(2, BASE_TIME + timedelta(seconds=30), event_type=EventType.LINK_UP)
    )
    cooldown_claim = restarted_engine.store.claim_notification(
        aggregate_id, BASE_TIME + timedelta(seconds=319)
    )
    next_claim = restarted_engine.store.claim_notification(
        aggregate_id, BASE_TIME + timedelta(seconds=320)
    )

    assert duplicate.duplicate is True
    assert second.alert is not None
    assert second.alert.count == 2
    assert len(restarted_engine.store.trace_events(aggregate_id)) == 2
    assert cooldown_claim.allowed is False
    assert next_claim.allowed is True


def test_grouping_separates_device_and_interface(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "groups.db")

    engine.process(_event(1, BASE_TIME, device_name="sw-01", interface_name="Gi0/1"))
    engine.process(_event(2, BASE_TIME, device_name="sw-01", interface_name="Gi0/2"))
    engine.process(_event(3, BASE_TIME, device_name="sw-02", interface_name="Gi0/1"))

    assert len(engine.store.list_alerts()) == 3


def test_rules_are_loaded_from_versioned_yaml() -> None:
    config = load_correlation_config(Path("config/correlation_rules.yaml"))

    assert config.schema_version == "1.0"
    assert len(config.rules) == 1
    assert config.rules[0].window_seconds == 60
    assert config.rules[0].notification_cooldown_seconds == 300


def test_event_without_required_interface_is_not_persisted(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "missing-field.db")
    event = _event(1, BASE_TIME).model_copy(update={"interface_name": None})

    result = engine.process(event)

    assert result.matched is False
    assert result.reason == "missing required correlation fields: interface_name"
    assert engine.store.list_alerts() == []


def test_notification_claim_rejects_ambiguous_naive_time(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "naive-time.db")
    result = engine.process(_event(1, BASE_TIME))
    assert result.alert is not None

    with pytest.raises(ValueError, match="timezone-aware"):
        engine.store.claim_notification(result.alert.aggregate_id, datetime(2026, 1, 1, 12, 0))
