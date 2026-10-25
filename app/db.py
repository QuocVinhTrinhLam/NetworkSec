"""Small SQLite repository. All values are passed as SQL parameters."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.models import Alert, AttackScenario, utc_now_iso

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS alerts (
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

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_notification ON alerts(notification_processed, timestamp);

CREATE TABLE IF NOT EXISTS notification_groups (
    fingerprint TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    window_started TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 1,
    message_ids_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS mutes (
    rule_id TEXT PRIMARY KEY,
    muted_until TEXT NOT NULL,
    muted_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technique TEXT NOT NULL,
    tool TEXT NOT NULL,
    expected_rule TEXT NOT NULL,
    detected INTEGER NOT NULL,
    detection_time_seconds REAL,
    notes TEXT NOT NULL DEFAULT '',
    tested_at TEXT NOT NULL
);
"""


class Database:
    """Repository wrapper that opens short-lived, thread-safe connections."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def insert_alert(self, alert: Alert) -> bool:
        record = alert.as_record()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, device_name, device_type, source_ip, dest_ip,
                    username, rule_id, rule_description, severity, mitre_id,
                    mitre_name, raw_log, use_case_id, recommended_response,
                    wazuh_level, groups_csv, created_at
                ) VALUES (
                    :id, :timestamp, :device_name, :device_type, :source_ip, :dest_ip,
                    :user, :rule_id, :rule_description, :severity, :mitre_id,
                    :mitre_name, :raw_log, :use_case_id, :recommended_response,
                    :wazuh_level, :groups, :created_at
                )
                """,
                {**record, "created_at": utc_now_iso()},
            )
            return cursor.rowcount == 1

    def pending_notifications(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM alerts
                WHERE notification_processed = 0
                ORDER BY timestamp ASC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_notification_processed(self, alert_id: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE alerts SET notification_processed = 1 WHERE id = ?", (alert_id,)
            )

    def get_notification_group(self, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM notification_groups WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return dict(row) if row else None

    def save_notification_group(
        self,
        fingerprint: str,
        alert_id: str,
        window_started: str,
        last_seen: str,
        alert_count: int,
        message_ids: dict[str, int] | None = None,
    ) -> None:
        message_ids_json = json.dumps(message_ids or {}, separators=(",", ":"))
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO notification_groups (
                    fingerprint, alert_id, window_started, last_seen,
                    alert_count, message_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    alert_id = excluded.alert_id,
                    window_started = excluded.window_started,
                    last_seen = excluded.last_seen,
                    alert_count = excluded.alert_count,
                    message_ids_json = excluded.message_ids_json
                """,
                (
                    fingerprint,
                    alert_id,
                    window_started,
                    last_seen,
                    alert_count,
                    message_ids_json,
                ),
            )

    def set_notification_message_ids(self, fingerprint: str, message_ids: dict[str, int]) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE notification_groups SET message_ids_json = ? WHERE fingerprint = ?",
                (json.dumps(message_ids, separators=(",", ":")), fingerprint),
            )

    def acknowledge(self, alert_id: str, actor: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
                WHERE id = ?
                """,
                (actor[:255], utc_now_iso(), alert_id),
            )
            return cursor.rowcount == 1

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def list_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 100)),)
            ).fetchall()
        return [dict(row) for row in rows]

    def search_alerts(
        self,
        *,
        hours: int | None = 24,
        severity: str = "",
        device: str = "",
        rule_id: str = "",
        source_ip: str = "",
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict[str, Any]], int]:
        """Filter alerts using a fixed clause allowlist and SQL parameters."""
        clauses: list[str] = []
        parameters: list[Any] = []
        if hours is not None:
            clauses.append("datetime(timestamp) >= datetime('now', ?)")
            parameters.append(f"-{max(1, hours)} hours")
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity)
        if device:
            clauses.append("device_name = ?")
            parameters.append(device)
        if rule_id:
            clauses.append("rule_id = ?")
            parameters.append(rule_id)
        if source_ip:
            clauses.append("source_ip = ?")
            parameters.append(source_ip)
        if search:
            clauses.append(
                """
                (rule_description LIKE ? ESCAPE '\\'
                 OR raw_log LIKE ? ESCAPE '\\'
                 OR device_name LIKE ? ESCAPE '\\')
                """
            )
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            parameters.extend([f"%{escaped}%"] * 3)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_page_size = max(1, min(page_size, 5000))
        offset = (max(1, page) - 1) * safe_page_size
        with self.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) AS total FROM alerts {where}", parameters
            ).fetchone()["total"]
            rows = connection.execute(
                f"""
                SELECT * FROM alerts {where}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, safe_page_size, offset],
            ).fetchall()
        return [dict(row) for row in rows], int(total)

    def top_sources(self, hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT source_ip, COUNT(*) AS alert_count
                FROM alerts
                WHERE source_ip IS NOT NULL
                  AND timestamp >= datetime('now', ?)
                GROUP BY source_ip
                ORDER BY alert_count DESC, source_ip ASC
                LIMIT ?
                """,
                (f"-{max(1, hours)} hours", max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def basic_stats(self, hours: int = 24) -> dict[str, Any]:
        since = f"-{max(1, hours)} hours"
        with self.connect() as connection:
            severity = connection.execute(
                """
                SELECT severity, COUNT(*) AS alert_count FROM alerts
                WHERE timestamp >= datetime('now', ?)
                GROUP BY severity
                """,
                (since,),
            ).fetchall()
            devices = connection.execute(
                """
                SELECT device_type, COUNT(*) AS alert_count FROM alerts
                WHERE timestamp >= datetime('now', ?)
                GROUP BY device_type
                """,
                (since,),
            ).fetchall()
        return {
            "severity": {row["severity"]: row["alert_count"] for row in severity},
            "device_type": {row["device_type"]: row["alert_count"] for row in devices},
        }

    def dashboard_stats(self, hours: int = 24) -> dict[str, Any]:
        modifier = f"-{max(1, hours)} hours"
        with self.connect() as connection:
            total = connection.execute(
                """
                SELECT COUNT(*) AS total FROM alerts
                WHERE datetime(timestamp) >= datetime('now', ?)
                """,
                (modifier,),
            ).fetchone()["total"]
            severity = connection.execute(
                """
                SELECT severity AS label, COUNT(*) AS value FROM alerts
                WHERE datetime(timestamp) >= datetime('now', ?)
                GROUP BY severity ORDER BY value DESC
                """,
                (modifier,),
            ).fetchall()
            device_types = connection.execute(
                """
                SELECT device_type AS label, COUNT(*) AS value FROM alerts
                WHERE datetime(timestamp) >= datetime('now', ?)
                GROUP BY device_type ORDER BY value DESC
                """,
                (modifier,),
            ).fetchall()
            top_sources = connection.execute(
                """
                SELECT COALESCE(source_ip, 'unknown') AS label, COUNT(*) AS value
                FROM alerts WHERE datetime(timestamp) >= datetime('now', ?)
                GROUP BY source_ip ORDER BY value DESC LIMIT 10
                """,
                (modifier,),
            ).fetchall()
            top_rules = connection.execute(
                """
                SELECT rule_id || ' — ' || rule_description AS label, COUNT(*) AS value
                FROM alerts WHERE datetime(timestamp) >= datetime('now', ?)
                GROUP BY rule_id, rule_description ORDER BY value DESC LIMIT 10
                """,
                (modifier,),
            ).fetchall()
            timeline = connection.execute(
                """
                SELECT strftime('%Y-%m-%d %H:00', timestamp) AS label,
                       COUNT(*) AS value
                FROM alerts WHERE datetime(timestamp) >= datetime('now', ?)
                GROUP BY label ORDER BY label ASC
                """,
                (modifier,),
            ).fetchall()

            # Tạo chuỗi bucket giờ liên tục cho toàn bộ cửa sổ quan sát (hours)
            # Giúp biểu đồ đường hiển thị đầy đủ 24 mốc giờ (kể cả giờ không có cảnh báo: value = 0)
            now_dt = datetime.now(UTC)
            timeline_buckets: dict[str, int] = {}
            for h in range(hours - 1, -1, -1):
                bucket_time = now_dt - timedelta(hours=h)
                bucket_label = bucket_time.strftime("%Y-%m-%d %H:00")
                timeline_buckets[bucket_label] = 0

            # Cập nhật số lượng sự kiện thực tế từ cơ sở dữ liệu vào các bucket tương ứng
            for row in timeline:
                row_dict = dict(row)
                lbl = row_dict["label"]
                timeline_buckets[lbl] = int(row_dict["value"])

            timeline_data = [
                {"label": lbl, "value": val}
                for lbl, val in sorted(timeline_buckets.items())
            ]
        return {
            "total": int(total),
            "severity": [dict(row) for row in severity],
            "device_types": [dict(row) for row in device_types],
            "top_sources": [dict(row) for row in top_sources],
            "top_rules": [dict(row) for row in top_rules],
            "timeline": timeline_data,
        }

    def devices(self, silent_minutes: int) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT device_name, device_type, MAX(timestamp) AS last_seen,
                       COUNT(*) AS alert_count
                FROM alerts GROUP BY device_name, device_type
                ORDER BY last_seen DESC
                """
            ).fetchall()
        devices: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                last_seen = datetime.fromisoformat(str(item["last_seen"]).replace("Z", "+00:00"))
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=UTC)
                age_minutes = (now - last_seen.astimezone(UTC)).total_seconds() / 60
            except ValueError:
                age_minutes = float("inf")
            item["status"] = "silent" if age_minutes > max(1, silent_minutes) else "active"
            item["age_minutes"] = round(age_minutes, 1)
            devices.append(item)
        return devices

    def list_scenarios(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM attack_scenarios ORDER BY tested_at DESC, id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def mute_rule(self, rule_id: str, minutes: int, actor: str) -> None:
        until = datetime.now(UTC).timestamp() + max(1, min(minutes, 10080)) * 60
        muted_until = datetime.fromtimestamp(until, UTC).isoformat(timespec="seconds")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO mutes(rule_id, muted_until, muted_by) VALUES (?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    muted_until = excluded.muted_until,
                    muted_by = excluded.muted_by
                """,
                (rule_id[:64], muted_until, actor[:255]),
            )

    def is_rule_muted(self, rule_id: str, now: datetime | None = None) -> bool:
        check_time = (now or datetime.now(UTC)).isoformat(timespec="seconds")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM mutes WHERE rule_id = ? AND muted_until > ?",
                (rule_id, check_time),
            ).fetchone()
        return row is not None

    def get_state(self, key: str) -> str | None:
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_state(self, key: str, value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO app_state(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, utc_now_iso()),
            )

    def add_scenario(self, scenario: AttackScenario) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO attack_scenarios (
                    technique, tool, expected_rule, detected,
                    detection_time_seconds, notes, tested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scenario.technique,
                    scenario.tool,
                    scenario.expected_rule,
                    int(scenario.detected),
                    scenario.detection_time_seconds,
                    scenario.notes,
                    scenario.tested_at,
                ),
            )
            return int(cursor.lastrowid)

    @staticmethod
    def parse_message_ids(raw: str) -> dict[str, int]:
        try:
            value = json.loads(raw)
            return {str(key): int(item) for key, item in value.items()}
        except (ValueError, TypeError, json.JSONDecodeError):
            return {}
