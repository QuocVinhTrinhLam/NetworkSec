from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.parsers import parse_syslog
from app.schemas.event import EventOutcome, EventType, EventVendor, NormalizedEvent, ParseStatus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "logs"
CISCO = (FIXTURES / "cisco-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
MIKROTIK = (FIXTURES / "mikrotik-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
MIKROTIK_DUAL = (
    (FIXTURES / "mikrotik-ospf-dual-synthetic.log").read_text(encoding="utf-8").splitlines()
)
RECEIVED_AT = datetime(2026, 11, 23, 12, 1, tzinfo=UTC)
UTC_PLUS_7 = timezone(timedelta(hours=7))


@pytest.mark.parametrize(
    ("line", "previous", "current", "event_type", "outcome"),
    [
        (0, "FULL", "DOWN", EventType.ROUTING_NEIGHBOR_DOWN, EventOutcome.FAILURE),
        (1, "LOADING", "FULL", EventType.ROUTING_NEIGHBOR_UP, EventOutcome.SUCCESS),
        (2, "FULL", "EXSTART", EventType.ROUTING_NEIGHBOR_STATE_CHANGE, EventOutcome.UNKNOWN),
        (3, "EXSTART", "EXCHANGE", EventType.ROUTING_NEIGHBOR_STATE_CHANGE, EventOutcome.UNKNOWN),
        (4, "EXCHANGE", "LOADING", EventType.ROUTING_NEIGHBOR_STATE_CHANGE, EventOutcome.UNKNOWN),
    ],
)
def test_cisco_ospf_synthetic_fixture(
    line: int, previous: str, current: str, event_type: EventType, outcome: EventOutcome
) -> None:
    result = parse_syslog(CISCO[line], received_at=RECEIVED_AT, source_host="R2")

    assert result.status is ParseStatus.PARSED
    event = result.event
    assert event is not None
    assert event.schema_version == "1.1"
    assert event.vendor is EventVendor.CISCO
    assert event.interface_name == "GigabitEthernet0/1"
    assert event.device_name == "R2"
    assert event.rule_id == "OSPF-5-ADJCHG"
    assert event.routing_protocol == "ospf"
    assert str(event.neighbor_router_id) == "192.0.2.1"
    assert event.ospf_area is None and event.local_router_id is None
    assert event.neighbor_ip is None and event.source_ip is None and event.interface_state is None
    assert (event.previous_state, event.current_state) == (previous, current)
    assert (event.event_type, event.outcome) == (event_type, outcome)
    assert event.raw_message == CISCO[line]


@pytest.mark.parametrize(
    ("line", "previous", "current", "event_type", "second", "vendor_severity"),
    [
        (0, "FULL", "DOWN", EventType.ROUTING_NEIGHBOR_DOWN, 0, "info"),
        (1, "LOADING", "FULL", EventType.ROUTING_NEIGHBOR_UP, 5, None),
        (2, "DOWN", "INIT", EventType.ROUTING_NEIGHBOR_STATE_CHANGE, 1, "debug"),
        (3, "INIT", "2-WAY", EventType.ROUTING_NEIGHBOR_STATE_CHANGE, 2, "debug"),
    ],
)
def test_mikrotik_ospf_synthetic_fixture(
    line: int,
    previous: str,
    current: str,
    event_type: EventType,
    second: int,
    vendor_severity: str | None,
) -> None:
    # The worker receives parse_message without PRI. The direct parser accepts either form.
    raw = MIKROTIK[line].removeprefix("<134>")
    result = parse_syslog(
        raw, received_at=RECEIVED_AT, source_timezone=UTC_PLUS_7, source_host="R1"
    )

    assert result.status is ParseStatus.PARSED
    event = result.event
    assert event is not None
    assert event.schema_version == "1.1"
    assert event.vendor is EventVendor.MIKROTIK
    assert event.timestamp == datetime(2026, 11, 23, 12, 0, second, tzinfo=UTC)
    assert event.device_name == "R1"
    assert event.interface_name == "ether3"
    assert event.routing_protocol == "ospf"
    assert str(event.ospf_area) == "0.0.0.0"
    assert str(event.local_router_id) == "192.0.2.1"
    assert str(event.neighbor_router_id) == "192.0.2.2"
    assert event.neighbor_ip is None and event.source_ip is None and event.interface_state is None
    assert (event.previous_state, event.current_state) == (previous, current)
    assert (event.event_type, event.vendor_severity) == (event_type, vendor_severity)
    assert event.raw_message == raw


@pytest.mark.parametrize(
    ("line", "device", "interface", "local_id", "peer_id", "event_type"),
    [
        (0, "R1", "ether3", "192.0.2.1", "192.0.2.2", EventType.ROUTING_NEIGHBOR_DOWN),
        (1, "R2", "ether4", "192.0.2.2", "192.0.2.1", EventType.ROUTING_NEIGHBOR_DOWN),
        (
            2,
            "R1",
            "ether3",
            "192.0.2.1",
            "192.0.2.2",
            EventType.ROUTING_NEIGHBOR_STATE_CHANGE,
        ),
        (
            3,
            "R2",
            "ether4",
            "192.0.2.2",
            "192.0.2.1",
            EventType.ROUTING_NEIGHBOR_STATE_CHANGE,
        ),
        (4, "R1", "ether3", "192.0.2.1", "192.0.2.2", EventType.ROUTING_NEIGHBOR_UP),
        (5, "R2", "ether4", "192.0.2.2", "192.0.2.1", EventType.ROUTING_NEIGHBOR_UP),
    ],
)
def test_dual_mikrotik_fixture_stays_on_routeros_parser(
    line: int,
    device: str,
    interface: str,
    local_id: str,
    peer_id: str,
    event_type: EventType,
) -> None:
    raw = MIKROTIK_DUAL[line].removeprefix("<134>")

    result = parse_syslog(raw, received_at=RECEIVED_AT, source_host="transport-fallback")

    assert result.status is ParseStatus.PARSED
    assert result.parser_name == "mikrotik_routeros"
    event = result.event
    assert event is not None
    assert (event.vendor, event.product) == (EventVendor.MIKROTIK, "RouterOS")
    assert (event.device_name, event.interface_name) == (device, interface)
    assert (str(event.local_router_id), str(event.neighbor_router_id)) == (local_id, peer_id)
    assert str(event.ospf_area) == "0.0.0.0"
    assert event.event_type is event_type


@pytest.mark.parametrize(
    "raw",
    [
        CISCO[1],
        CISCO[1].removeprefix("<189>"),
        MIKROTIK[0],
        MIKROTIK[1],
        MIKROTIK[0].replace("+07:00", "Z"),
    ],
)
def test_ospf_replay_identity_and_json_round_trip(raw: str) -> None:
    first = parse_syslog(raw, received_at=RECEIVED_AT).event
    replay = parse_syslog(raw, received_at=RECEIVED_AT + timedelta(hours=1)).event

    assert first is not None and replay is not None
    assert first.received_at != replay.received_at
    assert first.event_id == replay.event_id
    assert NormalizedEvent.model_validate_json(first.model_dump_json()) == first


@pytest.mark.parametrize(
    "raw",
    [
        CISCO[0].replace("192.0.2.1", "2001:db8::1"),
        CISCO[0].replace("to DOWN", "to"),
        CISCO[0].replace("to DOWN", "to UP"),
        CISCO[0].replace("to DOWN", "to FULL"),
        CISCO[1].replace("<189>", "<192>"),
        MIKROTIK[0].replace("192.0.2.1", "999.0.2.1"),
        MIKROTIK[0].replace("192.0.2.2", "not-a-router-id"),
        MIKROTIK[0].replace("0.0.0.0 }", "backbone }"),
        MIKROTIK[0].replace("198.51.100.1%", "999.51.100.1%"),
        MIKROTIK[0].replace("23T19", "99T19"),
        MIKROTIK[0].replace("%ether3", "%"),
    ],
)
def test_malformed_ospf_keeps_raw_without_an_event(raw: str) -> None:
    result = parse_syslog(raw, received_at=RECEIVED_AT)

    assert result.status is ParseStatus.MALFORMED
    assert result.event is None
    assert result.raw_message == raw


@pytest.mark.parametrize(
    "raw",
    [
        CISCO[0].replace("OSPF-5-ADJCHG", "OSPF-4-ERRRCV"),
        MIKROTIK[0].replace("version: 2", "version: 3"),
        MIKROTIK[0].replace("route,ospf,info", "script,info"),
        MIKROTIK[0].split(" neighbor {")[0] + " state change to Down",
        MIKROTIK[0].rsplit(" state change to", 1)[0] + " received wrong LS Ack",
        "Nov 23 19:00:00 R1 route,ospf,debug SEND: Hello Packet",
    ],
)
def test_non_ospfv2_neighbor_transition_is_unknown(raw: str) -> None:
    result = parse_syslog(raw, received_at=RECEIVED_AT)

    assert result.status is ParseStatus.UNKNOWN
    assert result.event is None


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "1.0"},
        {"schema_version": "2.0"},
        {"routing_protocol": "bgp"},
        {"neighbor_router_id": None},
        {"ospf_area": 0},
        {"neighbor_ip": "2001:db8::1"},
        {"previous_state": None},
        {"current_state": "UP"},
        {"current_state": "INIT"},
        {"outcome": "success"},
    ],
)
def test_ospf_version_and_metadata_are_validated(changes: dict[str, object]) -> None:
    event = parse_syslog(MIKROTIK[0], received_at=RECEIVED_AT).event
    assert event is not None
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(event.model_dump() | changes)


def test_ospf_neighbor_ip_when_explicitly_supplied_is_independent_of_router_id() -> None:
    event = parse_syslog(MIKROTIK[0], received_at=RECEIVED_AT).event
    assert event is not None

    enriched = NormalizedEvent.model_validate(event.model_dump() | {"neighbor_ip": "198.51.100.2"})

    assert str(enriched.neighbor_ip) == "198.51.100.2"
    assert str(enriched.neighbor_router_id) == "192.0.2.2"
    assert enriched.source_ip is None
    assert enriched.event_id == event.event_id
