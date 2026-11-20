from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.parsers import parse_syslog
from app.schemas.event import (
    MAX_RAW_MESSAGE_BYTES,
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
    ParseStatus,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "logs"
RECEIVED_AT = datetime(2026, 10, 26, 13, 0, tzinfo=UTC)


def fixture_lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def parsed(raw_message: str, *, source_host: str | None = None) -> NormalizedEvent:
    result = parse_syslog(
        raw_message,
        received_at=RECEIVED_AT,
        source_host=source_host,
    )
    assert result.status is ParseStatus.PARSED, result
    assert result.event is not None
    assert result.event.raw_message == raw_message
    return result.event


def test_cisco_link_down_fixture() -> None:
    raw_message = fixture_lines("cisco-ios.log")[2]
    event = parsed(raw_message, source_host="core-switch-01")

    assert event.schema_version == "1.0"
    assert event.vendor is EventVendor.CISCO
    assert event.product == "IOS"
    assert event.event_type is EventType.LINK_DOWN
    assert event.severity is EventSeverity.HIGH
    assert event.outcome is EventOutcome.FAILURE
    assert event.device_name == "core-switch-01"
    assert event.interface_name == "GigabitEthernet0/2"
    assert event.interface_state == "down"
    assert event.rule_id == "LINK-3-UPDOWN"
    assert event.timestamp == datetime(2026, 10, 26, 12, 5, 41, 29_000, tzinfo=UTC)


def test_cisco_configuration_change_fixture() -> None:
    event = parsed(fixture_lines("cisco-ios.log")[1], source_host="core-switch-01")

    assert event.event_type is EventType.CONFIGURATION_CHANGE
    assert event.username == "netadmin"
    assert event.session == "vty0"
    assert str(event.source_ip) == "10.0.99.10"
    assert event.action == "configured"
    assert event.rule_id == "SYS-5-CONFIG_I"


def test_cisco_port_security_fixture() -> None:
    event = parsed(fixture_lines("cisco-ios.log")[3], source_host="access-switch-01")

    assert event.event_type is EventType.PORT_SECURITY
    assert event.severity is EventSeverity.CRITICAL
    assert event.outcome is EventOutcome.DENIED
    assert event.interface_name == "GigabitEthernet0/4"
    assert event.mac_address == "0050.56aa.bbcc"
    assert event.rule_id == "PORT_SECURITY-2-PSECURE_VIOLATION"


@pytest.mark.parametrize(
    ("line_number", "source_ip", "method", "severity"),
    [
        (0, "198.51.100.23", "ssh", EventSeverity.CRITICAL),
        (1, "198.51.100.31", "winbox", EventSeverity.MEDIUM),
    ],
)
def test_mikrotik_login_failure_fixtures(
    line_number: int,
    source_ip: str,
    method: str,
    severity: EventSeverity,
) -> None:
    event = parsed(fixture_lines("mikrotik.log")[line_number], source_host="edge-router-01")

    assert event.vendor is EventVendor.MIKROTIK
    assert event.product == "RouterOS"
    assert event.event_type is EventType.LOGIN_FAILURE
    assert event.outcome is EventOutcome.FAILURE
    assert event.username == "admin"
    assert str(event.source_ip) == source_ip
    assert event.auth_method == method
    assert event.severity is severity
    assert event.timestamp == datetime(
        2026, 10, 26, 12, 1 if line_number == 0 else 3, 7 if line_number == 0 else 5, tzinfo=UTC
    )


@pytest.mark.parametrize("line_number", [0, 2])
def test_pfsense_acl_deny_fixtures(line_number: int) -> None:
    raw_message = fixture_lines("pfsense-opnsense.log")[line_number]
    event = parsed(raw_message)

    expected = {
        0: ("203.0.113.45", "10.0.10.20", 51514, 22, "1000000103"),
        2: ("203.0.113.99", "10.0.20.10", 42420, 443, "1000000105"),
    }[line_number]
    assert event.vendor is EventVendor.PFSENSE
    assert event.product == "pfSense"
    assert event.event_type is EventType.ACL_DENY
    assert event.outcome is EventOutcome.DENIED
    assert event.action == "block"
    assert event.direction == "in"
    assert event.interface_name == "em0"
    assert event.protocol == "tcp"
    assert str(event.source_ip) == expected[0]
    assert str(event.destination_ip) == expected[1]
    assert event.source_port == expected[2]
    assert event.destination_port == expected[3]
    assert event.rule_id == expected[4]
    assert event.rule_tracker == "1000000004"


@pytest.mark.parametrize(
    "raw_message",
    [
        fixture_lines("cisco-ios.log")[0],
        fixture_lines("cisco-ios.log")[4],
        fixture_lines("pfsense-opnsense.log")[1],
        fixture_lines("pfsense-opnsense.log")[3],
        fixture_lines("openvswitch.log")[0],
    ],
)
def test_known_but_unsupported_fixture_is_safe(raw_message: str) -> None:
    result = parse_syslog(raw_message, received_at=RECEIVED_AT)

    assert result.status is ParseStatus.UNKNOWN
    assert result.event is None
    assert result.raw_message == raw_message


@pytest.mark.parametrize(
    ("raw_message", "reason"),
    [
        ("", "empty_message"),
        ("bad\nsecond record", "invalid_record_delimiter"),
        ("Oct 26 12:05:41.029: %LINK-3-UPDOWN: Interface", "invalid_link_state"),
        (
            "oct/26/2026 12:01:07 system,error login failure for user admin from not-an-ip via ssh",
            "parser_validation_failed",
        ),
        (
            "Oct 26 12:00:01 edge-pfsense filterlog[1847]: 1,2,3",
            "short_filterlog_record",
        ),
        (
            "abc/26/2026 12:01:07 system,error login failure for user admin from 192.0.2.1 via ssh",
            "parser_validation_failed",
        ),
        ("invalid-surrogate-\ud800", "invalid_unicode"),
    ],
)
def test_malformed_records_return_diagnostics(raw_message: str, reason: str) -> None:
    result = parse_syslog(raw_message, received_at=RECEIVED_AT)

    assert result.status is ParseStatus.MALFORMED
    assert result.event is None
    assert result.raw_message == raw_message
    assert result.reason == reason


def test_oversized_record_is_rejected_before_regex_matching() -> None:
    raw_message = "x" * (MAX_RAW_MESSAGE_BYTES + 1)
    result = parse_syslog(raw_message, received_at=RECEIVED_AT)

    assert result.status is ParseStatus.MALFORMED
    assert result.reason == "message_too_large"
    assert result.raw_message is raw_message


def test_event_identity_is_stable_across_replay_receipt_time() -> None:
    raw_message = fixture_lines("cisco-ios.log")[2]
    first = parse_syslog(raw_message, received_at=RECEIVED_AT, source_host="switch-01")
    replay = parse_syslog(
        raw_message,
        received_at=datetime(2026, 10, 27, 13, 0, tzinfo=UTC),
        source_host="switch-01",
    )

    assert first.event is not None and replay.event is not None
    assert first.event.event_id == replay.event.event_id


def test_event_schema_forbids_unknown_fields() -> None:
    event = parsed(fixture_lines("mikrotik.log")[0], source_host="router-01")
    payload = event.model_dump()
    payload["unexpected"] = "not allowed"

    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(payload)


def test_event_json_schema_exposes_fixed_contract_versions() -> None:
    schema = NormalizedEvent.model_json_schema()

    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["properties"]["parser_version"]["const"] == "1.0"
