from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas.correlation import (
    CorrelationResult,
    OspfCorrelationConfig,
    OspfCorrelationSnapshot,
)
from app.schemas.event import EventSeverity, EventVendor, NormalizedEvent, OspfNeighborState
from app.services.correlation import CorrelationEngine, CorrelationStore, load_correlation_config

BASE_TIME = datetime(2026, 11, 23, 12, tzinfo=UTC)
RULES_PATH = Path("config/correlation_rules.yaml")
DOWN = OspfNeighborState.DOWN
FULL = OspfNeighborState.FULL
LINK = {
    "id": "r1-r2",
    "area": "0.0.0.0",
    "endpoints": (
        {"device_name": "R1", "interface_name": "ether3", "router_id": "192.0.2.1"},
        {"device_name": "R2", "interface_name": "Gi0/1", "router_id": "192.0.2.2"},
    ),
}


def _engine(
    tmp_path: Path, *, links: tuple[dict[str, object], ...] = (LINK,), scope: str = "lab"
) -> CorrelationEngine:
    store = CorrelationStore(tmp_path / "correlation.db")
    store.initialize()
    base = load_correlation_config(RULES_PATH)
    ospf = OspfCorrelationConfig.model_validate(
        {"scope": scope, "links": links, "max_clock_skew_seconds": 10}
    )
    return CorrelationEngine(store, base.model_copy(update={"ospf": ospf}))


def _event(
    state: OspfNeighborState,
    seconds: int,
    *,
    router: int = 1,
    interface: str | None = None,
    peer_id: str | None = None,
    received_seconds: int | None = None,
    tag: str = "",
) -> NormalizedEvent:
    event_type, outcome = state.classification
    name = f"R{router}"
    interface = interface or ("ether3" if router == 1 else "Gi0/1")
    timestamp = BASE_TIME + timedelta(seconds=seconds)
    received = BASE_TIME + timedelta(
        seconds=seconds if received_seconds is None else received_seconds
    )
    return NormalizedEvent(
        schema_version="1.1",
        timestamp=timestamp,
        received_at=received,
        vendor=EventVendor.MIKROTIK if router == 1 else EventVendor.CISCO,
        product="RouterOS" if router == 1 else "IOS",
        event_type=event_type,
        outcome=outcome,
        severity=EventSeverity.LOW,
        device_name=name,
        interface_name=interface,
        message=f"OSPF {state}",
        raw_message=f"{name} {interface} {seconds} OSPF {state} {tag}",
        parser_name="synthetic-correlation-fixture",
        routing_protocol="ospf",
        ospf_area="0.0.0.0" if router == 1 else None,
        local_router_id="192.0.2.1" if router == 1 else None,
        neighbor_router_id=peer_id or ("192.0.2.2" if router == 1 else "192.0.2.1"),
        previous_state=OspfNeighborState.LOADING if state is FULL else FULL,
        current_state=state,
    )


def _snapshot(result: CorrelationResult) -> OspfCorrelationSnapshot:
    assert result.matched
    assert result.alert is None
    assert result.ospf is not None
    return result.ospf


def test_both_sides_share_one_incident_across_windows_and_recover_independently(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path)
    first = _event(DOWN, 0)
    second = _event(DOWN, 120, router=2)
    third = _event(DOWN, 180, tag="another observation")
    first_snapshot = _snapshot(engine.process(first))
    assert engine.process(first).duplicate
    assert _snapshot(engine.process(first)) == first_snapshot
    assert not engine.process(second).duplicate
    after_down = _snapshot(engine.process(third))

    incident = after_down.incidents[0]
    assert after_down.adjacency.link_id == "r1-r2"
    assert incident.incident_id == first_snapshot.incidents[0].incident_id
    assert len(after_down.incidents) == 1
    assert incident.event_ids == (first.event_id, second.event_id, third.event_id)
    assert len(incident.reporters) == 2

    full_a = _event(FULL, 200)
    partial = _snapshot(engine.process(full_a)).incidents[0]
    assert partial.recovered_at is None
    assert partial.reporters[0].full_at == full_a.timestamp
    repeated_a = _event(FULL, 210)
    still_open = _snapshot(engine.process(repeated_a)).incidents[0]
    assert still_open.recovered_at is None
    assert still_open.reporters[0].full_at == full_a.timestamp

    full_b = _event(FULL, 220, router=2)
    closed = _snapshot(engine.process(full_b)).incidents[0]
    assert closed.incident_id == incident.incident_id
    assert closed.recovered_at == full_b.timestamp
    assert _snapshot(engine.process(_event(FULL, 230, router=2))).incidents == (closed,)
    new_down = _snapshot(engine.process(_event(DOWN, 231))).incidents
    assert len(new_down) == 2
    assert new_down[1].incident_id != incident.incident_id
    assert new_down[1].recovered_at is None
    assert engine.store.list_alerts() == []


def test_weak_identity_is_isolated_or_kept_as_telemetry(tmp_path: Path) -> None:
    engine = _engine(tmp_path, links=())
    local = _snapshot(engine.process(_event(DOWN, 0)))
    other_interface = _snapshot(engine.process(_event(DOWN, 1, interface="ether4")))
    other_neighbor = _snapshot(engine.process(_event(DOWN, 2, peer_id="192.0.2.3")))
    other_site = _snapshot(_engine(tmp_path, links=(), scope="another").process(_event(DOWN, 0)))
    other_area_event = _event(DOWN, 3, tag="non-backbone area")
    other_area = NormalizedEvent.model_validate(
        other_area_event.model_dump() | {"ospf_area": "0.0.0.1"}
    )
    assert (
        len(
            {
                local.adjacency_id,
                other_interface.adjacency_id,
                other_neighbor.adjacency_id,
                other_site.adjacency_id,
                _snapshot(engine.process(other_area)).adjacency_id,
            }
        )
        == 5
    )
    assert local.adjacency.local_interface == ("R1", "ether3")
    assert not engine.process(_event(DOWN, 4, router=2)).matched
    missing = NormalizedEvent.model_validate(
        _event(DOWN, 5).model_dump() | {"interface_name": None}
    )
    result = engine.process(missing)
    assert not result.matched and result.reason == "missing OSPF reporting device or interface"


def test_parallel_inventory_links_and_conflicting_metadata(tmp_path: Path) -> None:
    parallel = {
        "id": "parallel",
        "area": "0.0.0.0",
        "endpoints": (
            {"device_name": "R1", "interface_name": "ether4", "router_id": "192.0.2.1"},
            {"device_name": "R2", "interface_name": "Gi0/2", "router_id": "192.0.2.2"},
        ),
    }
    engine = _engine(tmp_path, links=(LINK, parallel))
    first = _snapshot(engine.process(_event(DOWN, 0)))
    second = _snapshot(engine.process(_event(DOWN, 1, interface="ether4")))
    assert first.adjacency_id != second.adjacency_id
    assert _snapshot(engine.process(_event(DOWN, 2, router=2))).adjacency_id == first.adjacency_id
    conflict = engine.process(_event(DOWN, 3, peer_id="192.0.2.3"))
    assert not conflict.matched and "conflicts with inventory" in (conflict.reason or "")

    ambiguous = _engine(tmp_path, links=(LINK, LINK | {"id": "ambiguous"}))
    result = ambiguous.process(_event(DOWN, 4, router=2))
    assert not result.matched and "ambiguous" in (result.reason or "")


def test_full_before_down_and_late_down_reconcile_after_restart(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    full_a = _event(FULL, 100)
    assert _snapshot(engine.process(full_a)).incidents == ()
    late_a = _event(DOWN, 10)
    first = _snapshot(engine.process(late_a))
    assert first.incidents[0].recovered_at == full_a.timestamp

    engine = _engine(tmp_path)
    assert engine.store.list_ospf_adjacencies() == (first.adjacency,)
    assert engine.store.ospf_snapshot(first.adjacency) == first
    late_b = _event(DOWN, 5, router=2)
    reopened = _snapshot(engine.process(late_b))
    assert reopened.revision > first.revision
    assert reopened.incidents[0].incident_id == first.incidents[0].incident_id
    assert reopened.incidents[0].first_down_at == late_b.timestamp
    assert reopened.incidents[0].recovered_at is None
    assert _snapshot(engine.process(full_a)) == reopened
    full_b = _event(FULL, 150, router=2)
    confirmed = _snapshot(engine.process(full_b))
    assert confirmed.incidents[0].recovered_at == full_b.timestamp
    assert confirmed.incidents[0].incident_id == first.incidents[0].incident_id


def test_late_down_can_reconcile_two_provisional_incidents(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    original = _snapshot(engine.process(_event(DOWN, 10)))
    engine.process(_event(FULL, 20))
    split = _snapshot(engine.process(_event(DOWN, 30)))
    assert len(split.incidents) == 2

    revised = _snapshot(engine.process(_event(DOWN, 15, router=2)))
    assert revised.revision > split.revision
    assert len(revised.incidents) == 1
    incident = revised.incidents[0]
    assert incident.incident_id == original.incidents[0].incident_id
    assert len(incident.reporters) == 2
    assert incident.recovered_at is None


@pytest.mark.parametrize("full_first", [True, False])
def test_equal_time_and_nonreporting_full_do_not_recover(tmp_path: Path, full_first: bool) -> None:
    engine = _engine(tmp_path)
    first, second = (_event(FULL, 1), _event(DOWN, 1))
    if not full_first:
        first, second = second, first
    engine.process(first)
    tied = _snapshot(engine.process(second)).incidents[0]
    assert tied.recovered_at is None
    assert tied.reporters[0].full_at is None
    assert _snapshot(engine.process(_event(FULL, 2, router=2))).incidents[0] == tied
    intermediate = engine.process(_event(OspfNeighborState.EXSTART, 3))
    assert not intermediate.matched and intermediate.ospf is None
    assert _snapshot(engine.process(_event(FULL, 4))).incidents[0].recovered_at is not None


def test_unreliable_timestamps_do_not_confirm_recovery(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    engine.process(_event(DOWN, 0))
    unreliable_full = _event(FULL, 100, received_seconds=1)
    doubtful = engine.process(unreliable_full)
    assert doubtful.reason == "unreliable OSPF event timestamp"
    assert _snapshot(doubtful).incidents[0].recovered_at is None

    uncertain_down = _event(DOWN, 100, router=2, received_seconds=2)
    engine.process(uncertain_down)
    engine.process(_event(FULL, 3))
    full_b = _event(FULL, 12, router=2)
    pending = _snapshot(engine.process(full_b))
    assert pending.unreliable_event_ids == (unreliable_full.event_id, uncertain_down.event_id)
    assert pending.incidents[0].reporters[1].uncertain_until == full_b.timestamp
    assert pending.incidents[0].recovered_at is None

    safe_full = _event(FULL, 13, router=2)
    assert _snapshot(engine.process(safe_full)).incidents[0].recovered_at == safe_full.timestamp


def test_newer_down_invalidates_one_sides_prior_full(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    for event in (
        _event(DOWN, 1),
        _event(DOWN, 2, router=2),
        _event(FULL, 3),
        _event(DOWN, 4),
    ):
        engine.process(event)
    now = _snapshot(engine.process(_event(FULL, 5, router=2))).incidents[0]
    assert now.reporters[0].full_at is None
    assert now.recovered_at is None
    assert _snapshot(engine.process(_event(FULL, 6))).incidents[0].recovered_at is not None
