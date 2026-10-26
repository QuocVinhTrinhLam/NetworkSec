import sqlite3
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


def test_initialize_migrates_existing_flat_alert_table(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                username TEXT,
                rule_id TEXT NOT NULL,
                rule_description TEXT NOT NULL,
                severity TEXT NOT NULL,
                mitre_id TEXT,
                mitre_name TEXT,
                raw_log TEXT NOT NULL,
                use_case_id TEXT,
                recommended_response TEXT,
                wazuh_level INTEGER NOT NULL,
                groups_csv TEXT NOT NULL DEFAULT '',
                acknowledged INTEGER NOT NULL DEFAULT 0,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                notification_processed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            INSERT INTO alerts (
                id, timestamp, device_name, device_type, source_ip, rule_id,
                rule_description, severity, raw_log, wazuh_level, created_at
            ) VALUES (
                'legacy-1', '2026-10-25T10:00:00+00:00', 'core-router',
                'router', '203.0.113.7', '100210', 'SSH brute force',
                'high', 'legacy line', 10, '2026-10-25T10:00:01+00:00'
            );
            """
        )

    database = Database(path)
    database.initialize()

    stored = database.get_alert("legacy-1")
    assert stored is not None
    assert stored["schema_version"] == "1.0"
    assert stored["received_at"] == "2026-10-25T10:00:01+00:00"
    assert len(stored["dedup_key"]) == 64
