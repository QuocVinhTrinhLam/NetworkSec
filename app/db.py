"""Small SQLite repository. All values are passed as SQL parameters."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.models import Alert, AttackScenario, utc_now_iso
from app.schemas.alert import AlertStatus, MitreTechnique

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
    created_at TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    received_at TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'mock',
    device_vendor TEXT,
    device_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    interface TEXT,
    vlan INTEGER,
    mitre_json TEXT NOT NULL DEFAULT '[]',
    event_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new',
    tags_json TEXT NOT NULL DEFAULT '[]',
    dedup_key TEXT NOT NULL DEFAULT ''
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

MIGRATION_COLUMNS = {
    "schema_version": "TEXT NOT NULL DEFAULT '1.0'",
    "received_at": "TEXT NOT NULL DEFAULT ''",
    "source": "TEXT NOT NULL DEFAULT 'mock'",
    "device_vendor": "TEXT",
    "device_ip": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "protocol": "TEXT",
    "interface": "TEXT",
    "vlan": "INTEGER",
    "mitre_json": "TEXT NOT NULL DEFAULT '[]'",
    "event_count": "INTEGER NOT NULL DEFAULT 1",
    "status": "TEXT NOT NULL DEFAULT 'new'",
    "tags_json": "TEXT NOT NULL DEFAULT '[]'",
    "dedup_key": "TEXT NOT NULL DEFAULT ''",
}


class Database:
    """Repository wrapper that opens short-lived, thread-safe connections."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            existing = {str(row["name"]) for row in connection.execute("PRAGMA table_info(alerts)")}
            for name, declaration in MIGRATION_COLUMNS.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {declaration}")
            connection.execute(
                """
                UPDATE alerts SET
                    received_at = CASE WHEN received_at = '' THEN created_at ELSE received_at END,
                    source = CASE WHEN id LIKE 'mock-%' THEN 'mock' ELSE source END,
                    status = CASE WHEN acknowledged = 1 THEN 'acknowledged' ELSE status END
                """
            )
            legacy_rows = connection.execute(
                """
                SELECT id, rule_id, device_name, source_ip, mitre_id, mitre_name
                FROM alerts WHERE dedup_key = '' OR (mitre_json = '[]' AND mitre_id IS NOT NULL)
                """
            ).fetchall()
            for row in legacy_rows:
                dedup_key = hashlib.sha256(
                    "\x1f".join(
                        (row["rule_id"], row["device_name"], row["source_ip"] or "")
                    ).encode("utf-8")
                ).hexdigest()
                mitre_json = "[]"
                if row["mitre_id"]:
                    mitre_json = json.dumps(
                        [
                            {
                                "id": row["mitre_id"],
                                "name": row["mitre_name"] or "Unknown",
                                "tactic": "Unknown",
                            }
                        ],
                        ensure_ascii=False,
                    )
                connection.execute(
                    "UPDATE alerts SET dedup_key = ?, mitre_json = ? WHERE id = ?",
                    (dedup_key, mitre_json, row["id"]),
                )

    @staticmethod
    def _record(alert: Alert) -> dict[str, Any]:
        first_mitre = alert.mitre[0] if alert.mitre else None
        return {
            "id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "device_name": alert.device.name,
            "device_type": alert.device.type.value,
            "source_ip": str(alert.network.src_ip) if alert.network.src_ip else None,
            "dest_ip": str(alert.network.dst_ip) if alert.network.dst_ip else None,
            "username": alert.user,
            "rule_id": alert.rule.id,
            "rule_description": alert.rule.description,
            "severity": alert.severity.value,
            "mitre_id": first_mitre.id if first_mitre else None,
            "mitre_name": first_mitre.name if first_mitre else None,
            "raw_log": alert.raw_log,
            "use_case_id": alert.rule.catalog_id,
            "recommended_response": None,
            "wazuh_level": alert.rule.level,
            "groups_csv": ",".join(alert.rule.groups),
            "acknowledged": int(alert.status is AlertStatus.ACKNOWLEDGED),
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": (
                alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
            ),
            "created_at": alert.received_at.isoformat(),
            "schema_version": alert.schema_version,
            "received_at": alert.received_at.isoformat(),
            "source": alert.source.value,
            "device_vendor": alert.device.vendor,
            "device_ip": str(alert.device.ip) if alert.device.ip else None,
            "src_port": alert.network.src_port,
            "dst_port": alert.network.dst_port,
            "protocol": alert.network.protocol,
            "interface": alert.network.interface,
            "vlan": alert.network.vlan,
            "mitre_json": json.dumps(
                [item.model_dump(mode="json") for item in alert.mitre], ensure_ascii=False
            ),
            "event_count": alert.event_count,
            "status": alert.status.value,
            "tags_json": json.dumps(alert.tags, ensure_ascii=False),
            "dedup_key": alert.dedup_key,
        }

    @staticmethod
    def _model(row: sqlite3.Row | dict[str, Any]) -> Alert:
        item = dict(row)
        return Alert.model_validate(
            {
                "schema_version": item.get("schema_version") or "1.0",
                "alert_id": item["id"],
                "timestamp": item["timestamp"],
                "received_at": item.get("received_at") or item["created_at"],
                "source": item.get("source") or "mock",
                "device": {
                    "name": item["device_name"],
                    "type": item["device_type"],
                    "vendor": item.get("device_vendor"),
                    "ip": item.get("device_ip"),
                },
                "severity": item["severity"],
                "rule": {
                    "id": item["rule_id"],
                    "description": item["rule_description"],
                    "level": int(item.get("wazuh_level") or 0),
                    "groups": [
                        value for value in str(item.get("groups_csv") or "").split(",") if value
                    ],
                    "catalog_id": item.get("use_case_id"),
                },
                "network": {
                    "src_ip": item.get("source_ip"),
                    "src_port": item.get("src_port"),
                    "dst_ip": item.get("dest_ip"),
                    "dst_port": item.get("dst_port"),
                    "protocol": item.get("protocol"),
                    "interface": item.get("interface"),
                    "vlan": item.get("vlan"),
                },
                "user": item.get("username"),
                "mitre": json.loads(item.get("mitre_json") or "[]"),
                "event_count": int(item.get("event_count") or 1),
                "status": item.get("status") or "new",
                "acknowledged_by": item.get("acknowledged_by"),
                "acknowledged_at": item.get("acknowledged_at"),
                "tags": json.loads(item.get("tags_json") or "[]"),
                "raw_log": item["raw_log"],
                "dedup_key": item.get("dedup_key") or "",
            }
        )

    @classmethod
    def _compat(cls, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        alert = cls._model(item)
        first_mitre: MitreTechnique | None = alert.mitre[0] if alert.mitre else None
        item.update(
            {
                "id": item["id"],
                "timestamp": alert.timestamp.isoformat(),
                "device_name": alert.device.name,
                "device_type": alert.device.type.value,
                "source_ip": str(alert.network.src_ip) if alert.network.src_ip else None,
                "dest_ip": str(alert.network.dst_ip) if alert.network.dst_ip else None,
                "user": alert.user,
                "rule_id": alert.rule.id,
                "rule_description": alert.rule.description,
                "severity": alert.severity.value,
                "mitre_id": first_mitre.id if first_mitre else None,
                "mitre_name": first_mitre.name if first_mitre else None,
                "use_case_id": alert.rule.catalog_id,
                "wazuh_level": alert.rule.level,
                "groups": list(alert.rule.groups),
                "count": alert.event_count,
                "acknowledged": alert.status is AlertStatus.ACKNOWLEDGED,
            }
        )
        return item

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
        record = self._record(alert)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, device_name, device_type, source_ip, dest_ip,
                    username, rule_id, rule_description, severity, mitre_id,
                    mitre_name, raw_log, use_case_id, recommended_response,
                    wazuh_level, groups_csv, acknowledged, acknowledged_by,
                    acknowledged_at, created_at, schema_version, received_at,
                    source, device_vendor, device_ip, src_port, dst_port,
                    protocol, interface, vlan, mitre_json, event_count,
                    status, tags_json, dedup_key
                ) VALUES (
                    :id, :timestamp, :device_name, :device_type, :source_ip, :dest_ip,
                    :username, :rule_id, :rule_description, :severity, :mitre_id,
                    :mitre_name, :raw_log, :use_case_id, :recommended_response,
                    :wazuh_level, :groups_csv, :acknowledged, :acknowledged_by,
                    :acknowledged_at, :created_at, :schema_version, :received_at,
                    :source, :device_vendor, :device_ip, :src_port, :dst_port,
                    :protocol, :interface, :vlan, :mitre_json, :event_count,
                    :status, :tags_json, :dedup_key
                )
                """,
                record,
            )
            inserted = cursor.rowcount == 1
            if inserted:
                connection.execute(
                    """
                    INSERT INTO app_state(key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    ("last_alert_time", alert.timestamp.isoformat(), utc_now_iso()),
                )
            return inserted

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
        return [self._compat(row) for row in rows]

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

    def delete_notification_group(self, fingerprint: str) -> None:
        """Discard an unsent aggregation group after rate-limit suppression."""
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM notification_groups WHERE fingerprint = ?", (fingerprint,)
            )

    def acknowledge(self, alert_id: str, actor: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE alerts SET acknowledged = 1, status = 'acknowledged',
                    acknowledged_by = ?, acknowledged_at = ?
                WHERE id = ?
                """,
                (actor[:255], utc_now_iso(), alert_id),
            )
            return cursor.rowcount == 1

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._compat(row) if row else None

    def resolve_alert_id(self, prefix: str) -> str | None:
        """Resolve one unique hexadecimal alert ID prefix for compact callbacks."""
        if not prefix or len(prefix) > 64 or any(char not in "0123456789abcdef" for char in prefix):
            return None
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id FROM alerts WHERE id LIKE ? LIMIT 2", (f"{prefix}%",)
            ).fetchall()
        return str(rows[0]["id"]) if len(rows) == 1 else None

    def list_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 100)),)
            ).fetchall()
        return [self._compat(row) for row in rows]

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
                 OR device_name LIKE ? ESCAPE '\\'
                 OR rule_id LIKE ? ESCAPE '\\'
                 OR source_ip LIKE ? ESCAPE '\\'
                 OR dest_ip LIKE ? ESCAPE '\\')
                """
            )
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            parameters.extend([f"%{escaped}%"] * 6)
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
        return [self._compat(row) for row in rows], int(total)

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
                {"label": lbl, "value": val} for lbl, val in sorted(timeline_buckets.items())
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

    def silent_devices(self, silent_minutes: int) -> list[dict[str, Any]]:
        """Return devices whose last real telemetry predates the silent threshold."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT device_name, device_type, device_vendor, device_ip,
                       MAX(timestamp) AS last_seen
                FROM alerts
                WHERE rule_id != 'SYSTEM_DEVICE_SILENT'
                GROUP BY device_name, device_type, device_vendor, device_ip
                HAVING datetime(MAX(timestamp)) < datetime('now', ?)
                ORDER BY last_seen ASC
                """,
                (f"-{max(1, silent_minutes)} minutes",),
            ).fetchall()
        return [dict(row) for row in rows]

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

    def unmute_rule(self, rule_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM mutes WHERE rule_id = ?", (rule_id[:64],))
            return cursor.rowcount == 1

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
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a scenario row ID")
            return cursor.lastrowid

    @staticmethod
    def parse_message_ids(raw: str) -> dict[str, int]:
        try:
            value = json.loads(raw)
            return {str(key): int(item) for key, item in value.items()}
        except (ValueError, TypeError, json.JSONDecodeError):
            return {}
