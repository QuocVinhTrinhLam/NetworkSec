"""QA dataset cases for parsed, malformed and reordered synthetic observations."""

from datetime import UTC, timedelta, timezone
from pathlib import Path
from random import Random

import pytest
from qa_synthetic import BASE, R1, R2, ios, ios_ospf, routeros_ospf, timestamp

from app.parsers import parse_syslog
from app.schemas.correlation import OspfCorrelationConfig
from app.schemas.event import MAX_RAW_MESSAGE_BYTES, NormalizedEvent
from app.services.correlation import CorrelationEngine, load_correlation_config

FIREWALL = (
    "Nov 23 12:00:00 qa-pfsense filterlog[8]: "
    "101,,,1001,em0,match,block,in,4,0x0,,44,12,0,none,6,tcp,60,"
    "203.0.113.7,198.51.100.20,51514,22,0,S,12,,42,,mss"
)
LOGIN = (
    "nov/23/2026 12:00:00 system,error,critical login failure for user qa "
    "from 198.51.100.23 via ssh"
)
UP = ios(0, "%LINK-3-UPDOWN: Interface Gi0/1, changed state to up")
DOWN = UP.replace("state to up", "state to down")


@pytest.mark.parametrize(
    ("raw", "vendor", "kind", "severity", "host"),
    [
        pytest.param(UP, "cisco", "link_up", "high", R2, id="cisco-up"),
        pytest.param(DOWN, "cisco", "link_down", "high", R2, id="cisco-down"),
        pytest.param(
            ios(0, "%SYS-5-CONFIG_I: Configured from console by qa on vty0 (192.0.2.20)"),
            "cisco",
            "configuration_change",
            "low",
            R2,
            id="cisco-config",
        ),
        pytest.param(
            ios(
                0,
                "%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, "
                "caused by MAC address 0050.56aa.bbcc on port Gi0/4.",
            ),
            "cisco",
            "port_security",
            "critical",
            R2,
            id="cisco-port-security",
        ),
        pytest.param(
            ios_ospf(0, "FULL", "DOWN"),
            "cisco",
            "routing_neighbor_down",
            "low",
            R2,
            id="cisco-neighbor-down",
        ),
        pytest.param(
            ios_ospf(0, "LOADING", "FULL"),
            "cisco",
            "routing_neighbor_up",
            "low",
            R2,
            id="cisco-neighbor-full",
        ),
        pytest.param(
            ios_ospf(0, "EXSTART", "EXCHANGE"),
            "cisco",
            "routing_neighbor_state_change",
            "low",
            R2,
            id="cisco-neighbor-intermediate",
        ),
        pytest.param(LOGIN, "mikrotik", "login_failure", "critical", R1, id="routeros-login"),
        pytest.param(
            routeros_ospf(0, "Full", "Down"),
            "mikrotik",
            "routing_neighbor_down",
            "low",
            R1,
            id="routeros-neighbor-down",
        ),
        pytest.param(
            routeros_ospf(0, "Loading", "Full"),
            "mikrotik",
            "routing_neighbor_up",
            "low",
            R1,
            id="routeros-neighbor-full",
        ),
        pytest.param(
            FIREWALL, "pfsense", "acl_deny", "medium", "qa-pfsense", id="pfsense-ipv4-block"
        ),
    ],
)
def test_synthetic_contract(raw: str, vendor: str, kind: str, severity: str, host: str) -> None:
    first = parse_syslog(raw, received_at=BASE, source_host=host)
    replay = parse_syslog(raw, received_at=BASE + timedelta(seconds=13), source_host=host)
    event = first.event
    assert event is not None and replay.event is not None
    assert (event.vendor, event.event_type, event.severity, event.device_name) == (
        vendor,
        kind,
        severity,
        host,
    )
    assert event.timestamp == BASE and event.raw_message == raw
    assert event.event_id == replay.event.event_id
    assert NormalizedEvent.model_validate_json(event.model_dump_json()) == event
    if kind.startswith("routing_neighbor_"):
        assert event.schema_version == "1.1" and event.routing_protocol == "ospf"
        assert str(event.neighbor_router_id) == ("192.0.2.1" if vendor == "cisco" else "192.0.2.2")
        assert str(event.ospf_area) == ("None" if vendor == "cisco" else "0.0.0.0")
    else:
        assert event.schema_version == "1.0" and "routing_protocol" not in event.model_dump()


@pytest.mark.parametrize(
    ("raw", "expected", "reason"),
    [
        pytest.param("", "malformed", "empty_message", id="empty"),
        pytest.param(
            DOWN.removeprefix("Nov 23 12:00:00.000000: "),
            "malformed",
            "invalid_cisco_header",
            id="missing-timestamp",
        ),
        pytest.param(DOWN + "\x00", "malformed", "invalid_record_delimiter", id="nul-delimiter"),
        pytest.param(
            FIREWALL.replace("qa-pfsense ", ""),
            "malformed",
            "invalid_filterlog_header",
            id="missing-firewall-host",
        ),
        pytest.param(
            FIREWALL.replace("203.0.113.7", "999.0.113.7"),
            "malformed",
            "parser_validation_failed",
            id="invalid-ip",
        ),
        pytest.param(
            FIREWALL.rsplit(": ", 1)[0] + ": 101,,,",
            "malformed",
            "short_filterlog_record",
            id="filterlog-truncated",
        ),
        pytest.param(
            "qa-unknown vendor report ☁", "unknown", "unsupported_format", id="unsupported-unicode"
        ),
        pytest.param("\ud800", "malformed", "invalid_unicode", id="invalid-unicode"),
        pytest.param(
            "é" * (MAX_RAW_MESSAGE_BYTES // 2 + 1),
            "malformed",
            "message_too_large",
            id="utf8-byte-overflow",
        ),
    ],
)
def test_invalid_synthetic_contract(raw: str, expected: str, reason: str) -> None:
    result = parse_syslog(raw, received_at=BASE)
    assert (result.status, result.reason, result.event, result.raw_message) == (
        expected,
        reason,
        None,
        raw,
    )


def test_missing_device_and_explicit_timezone() -> None:
    offset = timezone(timedelta(hours=7))
    event = parse_syslog(DOWN, received_at=BASE, source_timezone=offset).event
    assert event is not None and event.device_name is None
    assert event.timestamp == BASE - timedelta(hours=7)
    assert event.timestamp.tzinfo is UTC
    bad_routeros = parse_syslog(routeros_ospf(0, "Full", "??"), received_at=BASE)
    assert bad_routeros.event is None


def test_bounded_seeded_syslog_mutations_have_total_dispatch() -> None:
    rng = Random(4206)
    seeds = (
        UP,
        DOWN,
        FIREWALL,
        LOGIN,
        ios_ospf(2, "FULL", "DOWN"),
        routeros_ospf(1, "Full", "Down"),
    )
    replacements = ("", "\n", "\x00", "火", "☁", '"', ",", "\ud800", "999", "%")
    for index in range(640):
        seed = seeds[index % len(seeds)]
        start = rng.randrange(len(seed))
        candidate = seed[:start] + rng.choice(replacements) + seed[start + rng.randrange(5) :]
        result = parse_syslog(candidate, received_at=BASE, source_host=R1)
        assert result.raw_message == candidate
        assert (result.event is not None) == (result.status == "parsed")
        if result.event:
            assert result.event.timestamp.utcoffset() == timedelta(0)


def test_reordered_synthetic_outages_areas_and_replay(tmp_path: Path) -> None:
    base = load_correlation_config(Path("config/correlation_rules.yaml"))
    ospf = OspfCorrelationConfig.model_validate(
        {
            "scope": "qa-synthetic-lab",
            "links": [
                {
                    "id": "qa-transit",
                    "area": "0.0.0.0",
                    "endpoints": [
                        {"device_name": R1, "interface_name": "ether3", "router_id": "192.0.2.1"},
                        {"device_name": R2, "interface_name": "Gi0/1", "router_id": "192.0.2.2"},
                    ],
                }
            ],
        }
    )
    engine = CorrelationEngine.from_files(tmp_path / "qa.db", Path("config/correlation_rules.yaml"))
    config = base.model_copy(update={"ospf": ospf})
    engine = CorrelationEngine(engine.store, config)

    def event(raw: str, host: str, second: float) -> NormalizedEvent:
        parsed = parse_syslog(raw, source_host=host, received_at=timestamp(second)).event
        assert parsed is not None
        return parsed

    r1_down = event(routeros_ospf(0, "Full", "Down"), R1, 0)
    r2_down = event(ios_ospf(70, "FULL", "DOWN"), R2, 70)
    r1_full = event(routeros_ospf(71, "Loading", "Full"), R1, 71)
    r2_stale = event(ios_ospf(65, "LOADING", "FULL"), R2, 72)
    r2_full = event(ios_ospf(73, "LOADING", "FULL"), R2, 74)
    other_down = event(
        routeros_ospf(1, "Full", "Down", area="0.0.0.1", peer="192.0.2.3", interface="ether4"),
        R1,
        1,
    )
    first = engine.process(r1_down).ospf
    other = engine.process(other_down).ospf
    assert first is not None and other is not None and first.adjacency_id != other.adjacency_id
    assert str(other.adjacency.area) == "0.0.0.1"
    assert engine.process(r1_down).duplicate
    engine.process(r2_down)
    engine.process(r1_full)
    engine = CorrelationEngine(engine.store, config)
    waiting = engine.process(r2_stale).ospf
    assert waiting is not None and waiting.incidents[0].recovered_at is None
    recovered = engine.process(r2_full).ospf
    assert recovered is not None
    assert recovered.incidents[0].incident_id == first.incidents[0].incident_id
    assert recovered.incidents[0].recovered_at == timestamp(73)
    assert engine.process(r2_full).duplicate
    flap = engine.process(event(ios_ospf(90, "FULL", "DOWN"), R2, 90)).ospf
    assert flap is not None and len(flap.incidents) == 2
    assert flap.incidents[1].recovered_at is None
