from pathlib import Path

from app.db import Database
from app.models import Alert


def test_insert_is_idempotent_and_acknowledge_is_parameterized(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.initialize()
    alert = Alert(
        id="same-id",
        timestamp="2026-10-25T10:00:00+00:00",
        device_name="router'; DROP TABLE alerts;--",
        device_type="router",
        source_ip="203.0.113.10",
        dest_ip="10.0.99.1",
        user="admin",
        rule_id="100210",
        rule_description="Brute force",
        severity="critical",
        mitre_id="T1110",
        mitre_name="Brute Force",
        raw_log="untrusted",
    )
    assert database.insert_alert(alert) is True
    assert database.insert_alert(alert) is False
    assert database.acknowledge(alert.id, "analyst") is True
    stored = database.get_alert(alert.id)
    assert stored is not None
    assert stored["device_name"] == "router'; DROP TABLE alerts;--"
    assert stored["acknowledged"] == 1
