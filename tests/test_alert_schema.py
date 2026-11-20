from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas.alert import Alert


def alert_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "timestamp": "2026-11-02T07:03:11.987Z",
        "received_at": "2026-11-02T07:03:12+00:00",
        "source": "mock",
        "device": {
            "name": "core-router",
            "type": "router",
            "vendor": "MikroTik",
            "ip": "10.0.99.1",
        },
        "severity": "critical",
        "rule": {
            "id": "100210",
            "description": "Repeated SSH authentication failures",
            "level": 13,
            "groups": ["authentication_failed", "brute_force"],
            "catalog_id": "ssh-bruteforce",
        },
        "network": {
            "src_ip": "203.0.113.5",
            "src_port": 51322,
            "dst_ip": "10.0.99.1",
            "dst_port": 22,
            "protocol": "tcp",
            "interface": "ether1",
            "vlan": 99,
        },
        "user": "admin",
        "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
        "event_count": 1,
        "status": "new",
        "acknowledged_by": None,
        "acknowledged_at": None,
        "tags": ["authentication", "internet-facing"],
        "raw_log": "login failure for user admin",
    }
    data.update(overrides)
    return data


def test_alert_normalizes_utc_and_validates_network_values() -> None:
    alert = Alert.model_validate(alert_data())

    assert alert.schema_version == "1.0"
    assert alert.timestamp == datetime(2026, 11, 2, 7, 3, 11, 987000, tzinfo=UTC)
    assert str(alert.network.src_ip) == "203.0.113.5"
    assert alert.network.dst_port == 22

    for invalid_network in (
        {"src_ip": "not-an-ip"},
        {"src_port": 0},
        {"dst_port": 65536},
    ):
        with pytest.raises(ValidationError):
            Alert.model_validate(alert_data(network=invalid_network))

    with pytest.raises(ValidationError, match="timezone"):
        Alert.model_validate(alert_data(timestamp="2026-11-02T07:03:11"))

    with pytest.raises(ValidationError):
        Alert.model_validate(alert_data(event_count=0))


def test_alert_id_is_deterministic_with_one_second_timestamp_bucket() -> None:
    first = Alert.model_validate(alert_data(timestamp="2026-11-02T07:03:11.001Z"))
    same_bucket = Alert.model_validate(
        alert_data(timestamp="2026-11-02T14:03:11.999+07:00", alert_id="caller-value")
    )
    next_bucket = Alert.model_validate(alert_data(timestamp="2026-11-02T07:03:12Z"))

    assert first.alert_id == same_bucket.alert_id
    assert first.alert_id != "caller-value"
    assert first.alert_id != next_bucket.alert_id
    assert first.dedup_key == next_bucket.dedup_key


def test_raw_log_uses_default_and_context_specific_limits() -> None:
    default = Alert.model_validate(alert_data(raw_log="x" * 5000))
    configured = Alert.model_validate(
        alert_data(raw_log="<script>" * 100),
        context={"raw_log_max_length": 32},
    )

    assert len(default.raw_log) == 4096
    assert len(configured.raw_log) == 32
    assert configured.raw_log.startswith("<script>")

    with pytest.raises(ValidationError, match="positive integer"):
        Alert.model_validate(
            alert_data(raw_log="event"),
            context={"raw_log_max_length": 0},
        )


def test_schema_rejects_unknown_fields_and_wrong_scalar_types() -> None:
    with pytest.raises(ValidationError):
        Alert.model_validate(alert_data(unexpected="value"))

    with pytest.raises(ValidationError):
        Alert.model_validate(alert_data(event_count="2"))
