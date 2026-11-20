"""PostgreSQL adapter for durable aggregated alert lifecycle state."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import EventSeverity, NormalizedEvent
from app.storage.base import AlertPage, AlertQuery, StorageError, StorageUnavailableError


class PostgresAlertStorage:
    """Persist aggregate state separately from Loki log payloads."""

    def __init__(self, dsn: str, migrations_path: Path, *, connect_timeout: int = 5) -> None:
        self.dsn = dsn
        self.migrations_path = migrations_path
        self.connect_timeout = connect_timeout

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        try:
            with psycopg.connect(
                self.dsn,
                connect_timeout=self.connect_timeout,
                row_factory=dict_row,
            ) as connection:
                yield connection
        except psycopg.OperationalError as exc:
            raise StorageUnavailableError("PostgreSQL is unavailable") from exc
        except psycopg.Error as exc:
            raise StorageError("PostgreSQL operation failed") from exc

    def migrate(self) -> None:
        migration_files = sorted(self.migrations_path.glob("*.sql"))
        if not migration_files:
            raise StorageError(f"no PostgreSQL migrations found in {self.migrations_path}")
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("networksec",))
            applied = {
                str(row["version"]): str(row["checksum"])
                for row in connection.execute(
                    "SELECT version, checksum FROM schema_migrations"
                ).fetchall()
            }
            for path in migration_files:
                sql = path.read_text(encoding="utf-8")
                checksum = hashlib.sha256(sql.encode()).hexdigest()
                if path.name in applied:
                    if applied[path.name] != checksum:
                        raise StorageError(f"applied migration checksum changed: {path.name}")
                    continue
                connection.execute(sql)
                connection.execute(
                    "INSERT INTO schema_migrations(version, checksum) VALUES (%s, %s)",
                    (path.name, checksum),
                )

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        """Create/update aggregate state and its immutable Loki event reference."""
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO aggregated_alerts (
                    aggregate_id, schema_version, rule_id, event_family, group_key,
                    device_name, interface_name, event_types, window_start, window_end,
                    event_count, first_seen, last_seen, severity,
                    notification_cooldown_seconds, last_notification_at,
                    notification_count, status_changed_at, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (aggregate_id) DO UPDATE SET
                    event_types = EXCLUDED.event_types,
                    event_count = GREATEST(aggregated_alerts.event_count, EXCLUDED.event_count),
                    first_seen = LEAST(aggregated_alerts.first_seen, EXCLUDED.first_seen),
                    last_seen = GREATEST(aggregated_alerts.last_seen, EXCLUDED.last_seen),
                    severity = CASE
                        WHEN CASE EXCLUDED.severity
                            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2 ELSE 1 END
                           > CASE aggregated_alerts.severity
                            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2 ELSE 1 END
                        THEN EXCLUDED.severity ELSE aggregated_alerts.severity END,
                    last_notification_at = CASE
                        WHEN EXCLUDED.last_notification_at IS NULL
                            THEN aggregated_alerts.last_notification_at
                        WHEN aggregated_alerts.last_notification_at IS NULL
                            OR EXCLUDED.last_notification_at
                               > aggregated_alerts.last_notification_at
                            THEN EXCLUDED.last_notification_at
                        ELSE aggregated_alerts.last_notification_at
                    END,
                    notification_count = GREATEST(
                        aggregated_alerts.notification_count, EXCLUDED.notification_count
                    ),
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    alert.aggregate_id,
                    alert.schema_version,
                    alert.rule_id,
                    alert.event_family,
                    json.dumps(alert.group_key),
                    alert.device_name,
                    alert.interface_name,
                    json.dumps([item.value for item in alert.event_types]),
                    alert.window_start,
                    alert.window_end,
                    alert.count,
                    alert.first_seen,
                    alert.last_seen,
                    alert.severity.value,
                    alert.notification_cooldown_seconds,
                    alert.last_notification_at,
                    alert.notification_count,
                    now,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO alert_event_refs(event_id, aggregate_id, event_timestamp)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (event.event_id, alert.aggregate_id, event.timestamp),
            )
            row = connection.execute(
                "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s",
                (alert.aggregate_id,),
            ).fetchone()
        if row is None:
            raise StorageError("PostgreSQL did not return the upserted alert")
        return _record(row)

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        clauses = ["last_seen >= %s", "first_seen <= %s"]
        parameters: list[Any] = [query.start, query.end]
        if query.severity is not None:
            clauses.append("severity = %s")
            parameters.append(query.severity.value)
        if query.status is not None:
            clauses.append("status = %s")
            parameters.append(query.status)
        if query.event_type is not None:
            clauses.append("event_types @> %s::jsonb")
            parameters.append(json.dumps([query.event_type.value]))
        if query.device_name is not None:
            clauses.append("device_name = %s")
            parameters.append(query.device_name)
        if query.interface_name is not None:
            clauses.append("interface_name = %s")
            parameters.append(query.interface_name)
        where = " AND ".join(clauses)
        offset = (query.page - 1) * query.page_size
        with self._connect() as connection:
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM aggregated_alerts WHERE {where}", parameters
            ).fetchone()
            rows = connection.execute(
                f"""
                SELECT * FROM aggregated_alerts WHERE {where}
                ORDER BY last_seen DESC, aggregate_id DESC
                LIMIT %s OFFSET %s
                """,
                [*parameters, query.page_size, offset],
            ).fetchall()
        total = int(total_row["total"]) if total_row else 0
        return AlertPage(tuple(_record(row) for row in rows), total)

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s", (aggregate_id,)
            ).fetchone()
        return _record(row) if row is not None else None

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        now = datetime.now(UTC)
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE aggregated_alerts SET
                    status = 'acknowledged', acknowledged_by = %s, acknowledged_at = %s,
                    status_changed_by = %s, status_changed_at = %s,
                    note = COALESCE(%s, note), updated_at = %s
                WHERE aggregate_id = %s
                RETURNING *
                """,
                (actor[:255], now, actor[:255], now, note, now, aggregate_id),
            ).fetchone()
        return _record(row) if row is not None else None

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        lifecycle = AlertLifecycleStatus(status)
        if lifecycle is AlertLifecycleStatus.ACKNOWLEDGED:
            return self.acknowledge(aggregate_id, actor, note)
        now = datetime.now(UTC)
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE aggregated_alerts SET
                    status = %s, status_changed_by = %s, status_changed_at = %s,
                    note = COALESCE(%s, note), updated_at = %s
                WHERE aggregate_id = %s
                RETURNING *
                """,
                (lifecycle.value, actor[:255], now, note, now, aggregate_id),
            ).fetchone()
        return _record(row) if row is not None else None

    def dashboard_stats(self, start: datetime, end: datetime) -> dict[str, Any]:
        overlap = "last_seen >= %s AND first_seen <= %s"
        parameters = (start, end)
        with self._connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) AS value FROM aggregated_alerts WHERE {overlap}",
                parameters,
            ).fetchone()
            severity = connection.execute(
                f"""
                SELECT severity AS label, COUNT(*) AS value
                FROM aggregated_alerts WHERE {overlap}
                GROUP BY severity ORDER BY value DESC
                """,
                parameters,
            ).fetchall()
            devices = connection.execute(
                f"""
                SELECT COALESCE(device_name, 'unknown') AS label, COUNT(*) AS value
                FROM aggregated_alerts WHERE {overlap}
                GROUP BY device_name ORDER BY value DESC, label LIMIT 10
                """,
                parameters,
            ).fetchall()
            event_types = connection.execute(
                f"""
                SELECT types.event_type AS label, COUNT(*) AS value
                FROM aggregated_alerts
                CROSS JOIN LATERAL jsonb_array_elements_text(event_types)
                    AS types(event_type)
                WHERE {overlap}
                GROUP BY types.event_type ORDER BY value DESC, label LIMIT 10
                """,
                parameters,
            ).fetchall()
            rules = connection.execute(
                f"""
                SELECT rule_id || ' — ' || event_family AS label, COUNT(*) AS value
                FROM aggregated_alerts WHERE {overlap}
                GROUP BY rule_id, event_family ORDER BY value DESC, label LIMIT 10
                """,
                parameters,
            ).fetchall()
            timeline = connection.execute(
                f"""
                SELECT to_char(date_trunc('hour', last_seen AT TIME ZONE 'UTC'),
                               'YYYY-MM-DD HH24:00') AS label,
                       COUNT(*) AS value
                FROM aggregated_alerts WHERE {overlap}
                GROUP BY date_trunc('hour', last_seen AT TIME ZONE 'UTC')
                ORDER BY date_trunc('hour', last_seen AT TIME ZONE 'UTC')
                """,
                parameters,
            ).fetchall()
        return {
            "total": int(total["value"]) if total else 0,
            "severity": [dict(row) for row in severity],
            "device_types": [dict(row) for row in devices],
            "top_devices": [dict(row) for row in devices],
            "top_rules": [dict(row) for row in rules],
            "event_types": [dict(row) for row in event_types],
            "timeline": [dict(row) for row in timeline],
            "top_sources": [],
        }

    def claim_notifications(
        self, minimum_severity: EventSeverity, now: datetime, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        minimum_rank = {
            EventSeverity.LOW: 1,
            EventSeverity.MEDIUM: 2,
            EventSeverity.HIGH: 3,
            EventSeverity.CRITICAL: 4,
        }[minimum_severity]
        with self._connect() as connection:
            rows = connection.execute(
                """
                WITH eligible AS (
                    SELECT aggregate_id
                    FROM aggregated_alerts
                    WHERE status != 'resolved'
                      AND event_count > last_notification_event_count
                      AND (
                          last_notification_at IS NULL
                          OR last_notification_at
                             + make_interval(secs => notification_cooldown_seconds) <= %s
                      )
                      AND CASE severity
                          WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                          WHEN 'medium' THEN 2 ELSE 1 END >= %s
                    ORDER BY CASE severity
                        WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                        WHEN 'medium' THEN 2 ELSE 1 END DESC,
                        last_seen ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE aggregated_alerts AS alert SET
                    last_notification_at = %s,
                    last_notification_event_count = alert.event_count,
                    notification_count = alert.notification_count + 1,
                    updated_at = %s
                FROM eligible
                WHERE alert.aggregate_id = eligible.aggregate_id
                RETURNING alert.*
                """,
                (now, minimum_rank, max(1, min(limit, 500)), now, now),
            ).fetchall()
        return tuple(_record(row) for row in rows)

    def get_telegram_message_id(self, aggregate_id: str, chat_id: int) -> int | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT message_id FROM telegram_message_state
                WHERE aggregate_id = %s AND chat_id = %s
                """,
                (aggregate_id, chat_id),
            ).fetchone()
        return int(row["message_id"]) if row else None

    def save_telegram_message_id(self, aggregate_id: str, chat_id: int, message_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO telegram_message_state(aggregate_id, chat_id, message_id)
                VALUES (%s, %s, %s)
                ON CONFLICT (aggregate_id, chat_id) DO UPDATE SET
                    message_id = EXCLUDED.message_id, updated_at = now()
                """,
                (aggregate_id, chat_id, message_id),
            )

    def ready(self) -> bool:
        try:
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone() is not None
        except StorageError:
            return False


def _record(row: dict[str, Any]) -> AlertRecord:
    event_types = row["event_types"]
    if isinstance(event_types, str):
        event_types = json.loads(event_types)
    return AlertRecord(
        aggregate_id=str(row["aggregate_id"]),
        schema_version=str(row["schema_version"]),
        rule_id=str(row["rule_id"]),
        event_family=str(row["event_family"]),
        device_name=row["device_name"],
        interface_name=row["interface_name"],
        event_types=tuple(event_types),
        window_start=row["window_start"],
        window_end=row["window_end"],
        count=int(row["event_count"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        severity=str(row["severity"]),
        status=str(row["status"]),
        acknowledged_by=row["acknowledged_by"],
        acknowledged_at=row["acknowledged_at"],
        status_changed_by=row["status_changed_by"],
        status_changed_at=row["status_changed_at"],
        note=row["note"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
