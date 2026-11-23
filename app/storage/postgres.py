"""PostgreSQL adapter for durable aggregated alert lifecycle state."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Interface
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from app.bot.notification_models import DeliveryResult, OspfNotification, OspfNotificationKind
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import (
    AggregatedAlert,
    OspfAdjacencyKey,
    OspfCorrelationSnapshot,
    OspfIncident,
    OspfReporterState,
)
from app.schemas.event import EventSeverity, EventType, NormalizedEvent
from app.storage.base import (
    AlertEvidence,
    AlertListMetadata,
    AlertPage,
    AlertQuery,
    AlertQueueSummary,
    AlertStatusChange,
    IncidentEventRef,
    OspfIncidentRecord,
    StorageError,
    StorageUnavailableError,
)

VISIBLE_ALERT = """
    NOT EXISTS (
        SELECT 1 FROM ospf_incidents
        WHERE ospf_incidents.aggregate_id = aggregated_alerts.aggregate_id
          AND superseded_at IS NOT NULL
    )
"""
SEVERITY_RANK = {
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}
OSPF_EDIT_LEASE = timedelta(minutes=10)


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
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("networksec",))
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
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
                INSERT INTO alert_event_refs(
                    event_id, aggregate_id, event_timestamp, source_ip, event_type
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO UPDATE SET
                    source_ip = COALESCE(alert_event_refs.source_ip, EXCLUDED.source_ip),
                    event_type = COALESCE(alert_event_refs.event_type, EXCLUDED.event_type)
                WHERE alert_event_refs.aggregate_id = EXCLUDED.aggregate_id
                  AND (alert_event_refs.event_type IS NULL OR
                       (alert_event_refs.source_ip IS NULL AND EXCLUDED.source_ip IS NOT NULL))
                """,
                (
                    event.event_id,
                    alert.aggregate_id,
                    event.timestamp,
                    event.source_ip,
                    event.event_type,
                ),
            )
            row = connection.execute(
                "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s",
                (alert.aggregate_id,),
            ).fetchone()
        if row is None:
            raise StorageError("PostgreSQL did not return the upserted alert")
        return _record(row)

    def apply_ospf_snapshot(self, snapshot: OspfCorrelationSnapshot) -> bool:
        """Apply a newer complete adjacency projection in one transaction."""
        now = datetime.now(UTC)
        with self._connect() as connection:
            accepted = connection.execute(
                """
                INSERT INTO ospf_adjacencies (adjacency_id, adjacency_key, revision)
                VALUES (%s, %s::jsonb, %s)
                ON CONFLICT (adjacency_id) DO UPDATE SET revision = EXCLUDED.revision
                WHERE ospf_adjacencies.revision < EXCLUDED.revision
                RETURNING adjacency_id
                """,
                (snapshot.adjacency_id, snapshot.adjacency.model_dump_json(), snapshot.revision),
            ).fetchone()
            if accepted is None:
                return False

            connection.execute(
                """
                UPDATE ospf_incidents SET superseded_at = %s
                WHERE adjacency_id = %s AND superseded_at IS NULL
                  AND NOT (aggregate_id::text = ANY(%s::text[]))
                """,
                (now, snapshot.adjacency_id, [item.incident_id for item in snapshot.incidents]),
            )
            connection.execute(
                """
                UPDATE ospf_incident_event_refs SET is_current = false
                WHERE adjacency_id = %s AND is_current
                """,
                (snapshot.adjacency_id,),
            )
            for incident in snapshot.incidents:
                self._upsert_ospf_incident(connection, snapshot, incident, now)
        return True

    @staticmethod
    def _upsert_ospf_incident(
        connection: Any,
        snapshot: OspfCorrelationSnapshot,
        incident: OspfIncident,
        now: datetime,
    ) -> None:
        incident_id = incident.incident_id
        first = incident.first_down_at
        last = max(item.observed_at for item in incident.evidence)
        last_exclusive = last + timedelta(microseconds=1)
        device, interface = snapshot.adjacency.local_interface or (None, None)
        event_types = sorted({item.event_type.value for item in incident.evidence})
        connection.execute(
            """
            INSERT INTO aggregated_alerts (
                aggregate_id, schema_version, rule_id, event_family, group_key, device_name,
                interface_name, event_types, window_start, window_end, event_count,
                first_seen, last_seen, severity, notification_cooldown_seconds,
                status_changed_at, created_at, updated_at
            ) VALUES (
                %s, '1.0', 'ospf-adjacency', 'routing_neighbor', %s::jsonb, %s, %s, %s::jsonb,
                %s, %s, %s, %s, %s, 'medium', 300, %s, %s, %s
            )
            ON CONFLICT (aggregate_id) DO UPDATE SET
                event_types = EXCLUDED.event_types, window_start = EXCLUDED.window_start,
                window_end = EXCLUDED.window_end, event_count = EXCLUDED.event_count,
                first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen,
                updated_at = EXCLUDED.updated_at
            WHERE (aggregated_alerts.event_types, aggregated_alerts.window_start,
                   aggregated_alerts.window_end, aggregated_alerts.event_count,
                   aggregated_alerts.first_seen, aggregated_alerts.last_seen)
                  IS DISTINCT FROM
                  (EXCLUDED.event_types, EXCLUDED.window_start, EXCLUDED.window_end,
                   EXCLUDED.event_count, EXCLUDED.first_seen, EXCLUDED.last_seen)
            """,
            (
                incident_id,
                snapshot.adjacency.model_dump_json(),
                device,
                interface,
                json.dumps(event_types),
                first,
                last_exclusive,
                len(incident.evidence),
                first,
                last,
                now,
                now,
                now,
            ),
        )
        prior = connection.execute(
            "SELECT technical_recovered_at FROM ospf_incidents WHERE aggregate_id = %s",
            (incident_id,),
        ).fetchone()
        connection.execute(
            """
            INSERT INTO ospf_incidents (
                aggregate_id, adjacency_id, reporters, technical_recovered_at
            )
            VALUES (%s, %s, %s::jsonb, %s)
            ON CONFLICT (aggregate_id) DO UPDATE SET
                reporters = EXCLUDED.reporters,
                technical_recovered_at = EXCLUDED.technical_recovered_at,
                superseded_at = NULL
            """,
            (
                incident_id,
                snapshot.adjacency_id,
                json.dumps([item.model_dump(mode="json") for item in incident.reporters]),
                incident.recovered_at,
            ),
        )
        connection.cursor().executemany(
            """
            INSERT INTO ospf_incident_event_refs (
                adjacency_id, aggregate_id, event_id, event_timestamp,
                reporter_router_id, event_type
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (aggregate_id, event_id) DO UPDATE SET is_current = true
            """,
            [
                (
                    snapshot.adjacency_id,
                    incident_id,
                    item.event_id,
                    item.timestamp,
                    item.reporter_router_id,
                    item.event_type,
                )
                for item in incident.evidence
            ],
        )
        previous_recovery = prior["technical_recovered_at"] if prior else None
        if previous_recovery is None and incident.recovered_at is not None:
            connection.execute(
                """
                UPDATE aggregated_alerts
                SET status = 'resolved', status_change_source = 'ospf_recovery',
                    status_changed_by = 'ospf-correlation', status_changed_at = %s, updated_at = %s
                WHERE aggregate_id = %s AND status IN ('new', 'acknowledged')
                """,
                (now, now, incident_id),
            )
        elif previous_recovery is not None and incident.recovered_at is None:
            connection.execute(
                """
                UPDATE aggregated_alerts AS alert
                SET status = prior.previous_status, status_change_source = 'ospf_reassessment',
                    status_changed_by = 'ospf-correlation', status_changed_at = %s, updated_at = %s
                FROM (
                    SELECT previous_status FROM alert_status_history
                    WHERE aggregate_id = %s AND source = 'ospf_recovery'
                    ORDER BY change_id DESC LIMIT 1
                ) AS prior
                WHERE alert.aggregate_id = %s AND alert.status = 'resolved'
                  AND alert.status_change_source = 'ospf_recovery'
                """,
                (now, now, incident_id, incident_id),
            )

    def get_ospf_incident(self, aggregate_id: str) -> OspfIncidentRecord | None:
        with self._connect() as connection:
            return self._ospf_incident(connection, aggregate_id)

    @staticmethod
    def _ospf_incident(connection: Any, aggregate_id: str) -> OspfIncidentRecord | None:
        row = connection.execute(
            """
                SELECT adjacency_key, technical_recovered_at, superseded_at, reporters,
                       COALESCE(
                           (SELECT jsonb_agg(to_jsonb(ref) ORDER BY event_timestamp, event_id)
                            FROM ospf_incident_event_refs AS ref
                            WHERE ref.aggregate_id = incident.aggregate_id), '[]'::jsonb
                       ) AS evidence
                FROM ospf_incidents AS incident JOIN ospf_adjacencies USING (adjacency_id)
                WHERE incident.aggregate_id = %s
                """,
            (aggregate_id,),
        ).fetchone()
        if row is None:
            return None
        return OspfIncidentRecord(
            adjacency=OspfAdjacencyKey.model_validate(row["adjacency_key"]),
            technical_recovered_at=row["technical_recovered_at"],
            superseded_at=row["superseded_at"],
            reporters=tuple(OspfReporterState.model_validate(item) for item in row["reporters"]),
            event_refs=tuple(
                IncidentEventRef(
                    event_id=item["event_id"],
                    timestamp=datetime.fromisoformat(item["event_timestamp"]),
                    reporter_router_id=IPv4Interface(item["reporter_router_id"]).ip,
                    event_type=EventType(item["event_type"]),
                    is_current=item["is_current"],
                )
                for item in row["evidence"]
            ),
        )

    def get_alert_history(self, aggregate_id: str) -> tuple[AlertStatusChange, ...]:
        with self._connect() as connection:
            return self._alert_history(connection, aggregate_id)

    @staticmethod
    def _alert_history(connection: Any, aggregate_id: str) -> tuple[AlertStatusChange, ...]:
        rows = connection.execute(
            """
                SELECT previous_status, status, source, actor, note, changed_at
                FROM alert_status_history WHERE aggregate_id = %s ORDER BY change_id
                """,
            (aggregate_id,),
        ).fetchall()
        return tuple(
            AlertStatusChange(
                previous_status=(
                    AlertLifecycleStatus(row["previous_status"]) if row["previous_status"] else None
                ),
                status=AlertLifecycleStatus(row["status"]),
                source=row["source"],
                actor=row["actor"],
                note=row["note"],
                changed_at=row["changed_at"],
            )
            for row in rows
        )

    def get_alert_evidence(self, aggregate_id: str) -> AlertEvidence | None:
        """Read an alert, current and historical evidence, and status history together."""
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            row = connection.execute(
                "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s", (aggregate_id,)
            ).fetchone()
            if row is None:
                return None
            ospf = self._ospf_incident(connection, aggregate_id)
            history = self._alert_history(connection, aggregate_id)
            if ospf is not None:
                return AlertEvidence(_record(row), ospf.event_refs, history, ospf)
            refs = connection.execute(
                """
                SELECT event_id, event_timestamp, event_type, host(source_ip) AS source_ip
                FROM alert_event_refs WHERE aggregate_id = %s
                ORDER BY event_timestamp, event_id
                """,
                (aggregate_id,),
            )
            return AlertEvidence(
                _record(row),
                tuple(
                    IncidentEventRef(
                        event_id=ref["event_id"],
                        timestamp=ref["event_timestamp"],
                        event_type=EventType(ref["event_type"]) if ref["event_type"] else None,
                        source_ip=ref["source_ip"],
                    )
                    for ref in refs
                ),
                history,
            )

    def queue_summary(self, start: datetime, end: datetime) -> AlertQueueSummary:
        with self._connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) FILTER (WHERE status = 'new') AS new,
                       COUNT(*) FILTER (WHERE status = 'acknowledged') AS acknowledged,
                       COUNT(*) FILTER (
                           WHERE status != 'resolved' AND severity IN ('high', 'critical')
                       ) AS high_priority,
                       COUNT(*) FILTER (
                           WHERE status = 'resolved' AND status_changed_at BETWEEN %s AND %s
                       ) AS recently_resolved
                FROM aggregated_alerts WHERE first_seen <= %s AND {VISIBLE_ALERT}
                """,
                (start, end, end),
            ).fetchone()
        return AlertQueueSummary(**row)

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        after_start = "last_seen >= %s"
        if query.include_active_before_start:
            after_start = "(last_seen >= %s OR status IN ('new', 'acknowledged'))"
        clauses = [after_start, "first_seen <= %s", VISIBLE_ALERT]
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
            clauses.append("(device_name = %s OR group_key->'router_ids' ? %s)")
            parameters.extend((query.device_name, query.device_name))
        if query.interface_name is not None:
            clauses.append("interface_name = %s")
            parameters.append(query.interface_name)
        if query.rule_id is not None:
            clauses.append("rule_id = %s")
            parameters.append(query.rule_id)
        if query.source_ip is not None:
            clauses.append(
                """
                EXISTS (SELECT 1 FROM alert_event_refs AS ref
                        WHERE ref.aggregate_id = aggregated_alerts.aggregate_id
                          AND ref.source_ip = %s::inet)
                """
            )
            parameters.append(query.source_ip)
        if query.search is not None:
            clauses.append(
                """
                (strpos(lower(concat_ws(' ', aggregate_id, rule_id, event_family, device_name,
                                        interface_name, note, event_types,
                                        replace(event_types::text, '_', ' '), group_key)),
                        lower(%s)) > 0
                 OR EXISTS (
                     SELECT 1 FROM alert_event_refs AS ref
                     WHERE ref.aggregate_id = aggregated_alerts.aggregate_id
                       AND strpos(host(ref.source_ip), lower(%s)) > 0
                 ))
                """
            )
            parameters.extend((query.search, query.search))
        where = " AND ".join(clauses)
        offset = (query.page - 1) * query.page_size
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            total_row = connection.execute(
                f"SELECT COUNT(*) AS total FROM aggregated_alerts WHERE {where}", parameters
            ).fetchone()
            rows = connection.execute(
                f"""
                SELECT page.*, adjacency.adjacency_key,
                       ARRAY(
                           SELECT DISTINCT host(ref.source_ip) FROM alert_event_refs AS ref
                           WHERE ref.aggregate_id = page.aggregate_id AND ref.source_ip IS NOT NULL
                           ORDER BY host(ref.source_ip)
                       ) AS source_ips
                FROM (
                    SELECT * FROM aggregated_alerts WHERE {where}
                    ORDER BY last_seen DESC, aggregate_id DESC LIMIT %s OFFSET %s
                ) AS page
                LEFT JOIN ospf_incidents AS incident USING (aggregate_id)
                LEFT JOIN ospf_adjacencies AS adjacency USING (adjacency_id)
                ORDER BY page.last_seen DESC, page.aggregate_id DESC
                """,
                [*parameters, query.page_size, offset],
            ).fetchall()
        total = int(total_row["total"]) if total_row else 0
        return AlertPage(
            tuple(_record(row) for row in rows),
            total,
            {
                row["aggregate_id"]: AlertListMetadata(
                    OspfAdjacencyKey.model_validate(row["adjacency_key"])
                    if row["adjacency_key"] is not None
                    else None,
                    tuple(row["source_ips"]),
                )
                for row in rows
            },
        )

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s", (aggregate_id,)
            ).fetchone()
        return _record(row) if row is not None else None

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        return self.update_status(aggregate_id, AlertLifecycleStatus.ACKNOWLEDGED, actor, note)

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        lifecycle = AlertLifecycleStatus(status)
        now = datetime.now(UTC)
        with self._connect() as connection:
            if lifecycle is AlertLifecycleStatus.ACKNOWLEDGED:
                # Check the current state under the same row lock used by Resolve.
                current = connection.execute(
                    "SELECT * FROM aggregated_alerts WHERE aggregate_id = %s FOR NO KEY UPDATE",
                    (aggregate_id,),
                ).fetchone()
                if current is None:
                    return None
                if current["status"] == AlertLifecycleStatus.RESOLVED:
                    return _record(current)

            row = connection.execute(
                """
                WITH requested AS (
                    SELECT %s::text AS status, %s::text AS actor,
                           %s::timestamptz AS changed_at, %s::text AS note
                )
                UPDATE aggregated_alerts AS alert SET
                    status = requested.status,
                    acknowledged_by = CASE
                        WHEN requested.status = 'acknowledged' AND alert.status != requested.status
                        THEN requested.actor ELSE alert.acknowledged_by END,
                    acknowledged_at = CASE
                        WHEN requested.status = 'acknowledged' AND alert.status != requested.status
                        THEN requested.changed_at ELSE alert.acknowledged_at END,
                    status_change_source = CASE WHEN alert.status != requested.status
                        THEN 'operator' ELSE alert.status_change_source END,
                    status_changed_by = CASE WHEN alert.status != requested.status
                        THEN requested.actor ELSE alert.status_changed_by END,
                    status_changed_at = CASE WHEN alert.status != requested.status
                        THEN requested.changed_at ELSE alert.status_changed_at END,
                    note = COALESCE(requested.note, alert.note),
                    updated_at = CASE
                        WHEN alert.status != requested.status OR
                             COALESCE(requested.note, alert.note) IS DISTINCT FROM alert.note
                        THEN requested.changed_at ELSE alert.updated_at END
                FROM requested WHERE alert.aggregate_id = %s
                RETURNING alert.*
                """,
                (lifecycle.value, actor[:255], now, note, aggregate_id),
            ).fetchone()
        return _record(row) if row is not None else None

    def dashboard_stats(self, start: datetime, end: datetime) -> dict[str, Any]:
        overlap = f"last_seen >= %s AND first_seen <= %s AND {VISIBLE_ALERT}"
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
        minimum_rank = SEVERITY_RANK[minimum_severity]
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                WITH eligible AS (
                    SELECT aggregate_id
                    FROM aggregated_alerts
                    WHERE status != 'resolved'
                      AND {VISIBLE_ALERT}
                      AND NOT EXISTS (
                          SELECT 1 FROM ospf_incidents
                          WHERE ospf_incidents.aggregate_id = aggregated_alerts.aggregate_id
                      )
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

    def claim_ospf_notification(
        self, chat_ids: tuple[int, ...], minimum_severity: EventSeverity, now: datetime
    ) -> OspfNotification | None:
        """Claim the oldest pending transition for one incident and destination."""
        token = uuid4()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT event.*, alert.first_seen, alert.severity,
                       adjacency.adjacency_key, destination.chat_id, telegram.message_id
                FROM ospf_notification_events AS event
                JOIN aggregated_alerts AS alert USING (aggregate_id)
                JOIN ospf_incidents AS incident USING (aggregate_id)
                JOIN ospf_adjacencies AS adjacency USING (adjacency_id)
                CROSS JOIN unnest(%s::bigint[]) AS destination(chat_id)
                LEFT JOIN telegram_message_state AS telegram
                    ON telegram.aggregate_id = event.aggregate_id
                   AND telegram.chat_id = destination.chat_id
                LEFT JOIN ospf_telegram_deliveries AS delivery
                    ON delivery.notification_id = event.notification_id
                   AND delivery.chat_id = destination.chat_id
                WHERE event.invalidated_at IS NULL AND (
                    telegram.message_id IS NOT NULL OR (
                        event.kind = 'down' AND incident.superseded_at IS NULL
                        AND alert.notification_count = 0
                        AND CASE alert.severity
                            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2 ELSE 1 END >= %s
                    )
                )
                AND (delivery.notification_id IS NULL OR (
                    delivery.available_at <= %s AND (
                        delivery.state = 'pending'
                        OR (delivery.state = 'claimed' AND delivery.operation = 'edit')
                    )
                ))
                AND NOT EXISTS (
                    SELECT 1 FROM ospf_notification_events AS prior
                    LEFT JOIN ospf_telegram_deliveries AS receipt
                        ON receipt.notification_id = prior.notification_id
                       AND receipt.chat_id = destination.chat_id
                    WHERE prior.aggregate_id = event.aggregate_id
                      AND prior.notification_id < event.notification_id
                      AND (
                          (prior.invalidated_at IS NULL AND (
                              receipt.state IS NULL OR receipt.state IN ('pending', 'claimed')
                          ))
                          OR (receipt.state = 'claimed' AND receipt.available_at > %s)
                      )
                )
                ORDER BY event.notification_id, destination.chat_id
                LIMIT 1 FOR UPDATE OF event SKIP LOCKED
                """,
                (list(chat_ids), SEVERITY_RANK[minimum_severity], now, now),
            ).fetchone()
            if row is None:
                return None
            operation = "send" if row["message_id"] is None else "edit"
            claimed = connection.execute(
                """
                INSERT INTO ospf_telegram_deliveries (
                    notification_id, chat_id, operation, state, claim_token, available_at
                ) VALUES (%s, %s, %s, 'claimed', %s, %s)
                ON CONFLICT (notification_id, chat_id) DO UPDATE SET
                    state = 'claimed', operation = EXCLUDED.operation,
                    claim_token = EXCLUDED.claim_token, available_at = EXCLUDED.available_at
                WHERE ospf_telegram_deliveries.available_at <= %s AND (
                    ospf_telegram_deliveries.state = 'pending' OR (
                        ospf_telegram_deliveries.state = 'claimed'
                        AND ospf_telegram_deliveries.operation = 'edit'
                    )
                )
                RETURNING claim_token
                """,
                (
                    row["notification_id"],
                    row["chat_id"],
                    operation,
                    token,
                    now + OSPF_EDIT_LEASE,
                    now,
                ),
            ).fetchone()
            if claimed is None:
                return None
            return OspfNotification(
                notification_id=row["notification_id"],
                aggregate_id=row["aggregate_id"],
                chat_id=row["chat_id"],
                claim_token=token,
                message_id=row["message_id"],
                kind=OspfNotificationKind(row["kind"]),
                occurred_at=row["occurred_at"],
                first_seen=row["first_seen"],
                adjacency=OspfAdjacencyKey.model_validate(row["adjacency_key"]),
                severity=EventSeverity(row["severity"]),
                actor=row["actor"],
            )

    def finish_ospf_notification(
        self,
        claim: OspfNotification,
        result: DeliveryResult,
        available_at: datetime,
        message_id: int | None = None,
    ) -> None:
        """Record the attempt result and any new message ID atomically."""
        with self._connect() as connection:
            completed = connection.execute(
                """
                UPDATE ospf_telegram_deliveries SET state = %s, available_at = %s
                WHERE notification_id = %s AND chat_id = %s
                  AND claim_token = %s AND state = 'claimed'
                RETURNING notification_id
                """,
                (result, available_at, claim.notification_id, claim.chat_id, claim.claim_token),
            ).fetchone()
            if completed is not None and result == "delivered" and claim.message_id is None:
                if message_id is None:
                    raise ValueError("a delivered first send requires a Telegram message ID")
                connection.execute(
                    """
                    INSERT INTO telegram_message_state(aggregate_id, chat_id, message_id)
                    VALUES (%s, %s, %s) ON CONFLICT (aggregate_id, chat_id) DO NOTHING
                    """,
                    (claim.aggregate_id, claim.chat_id, message_id),
                )

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
