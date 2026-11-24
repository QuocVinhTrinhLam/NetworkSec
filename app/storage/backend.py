"""PostgreSQL registry, event catalogue and operational queries."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from app.schemas.api import AlertRecord
from app.schemas.backend import (
    CATEGORIES,
    AuditRecord,
    DeviceActivity,
    DeviceCreate,
    DevicePatch,
    DeviceRecord,
    EventRelations,
    IndexedEvent,
    Page,
    TrendPoint,
)
from app.schemas.correlation import (
    AggregatedAlert,
    CorrelationConfig,
    OspfCorrelationConfig,
    OspfCorrelationSnapshot,
)
from app.schemas.event import NormalizedEvent
from app.services.backend import EventFilters, device_status, redact, request_id, transport_address
from app.services.managed_rules import RuleCreate, RulePatch, RuleRecord
from app.services.ospf_correlation import ospf_adjacency_id, resolve_ospf_identity
from app.storage.base import StorageError
from app.storage.interface_state import record_interface_observation
from app.storage.managed_rules import correlate_event, rule_records, save_rule
from app.storage.postgres import VISIBLE_ALERT, PostgresAlertStorage, _record


class DuplicateResource(StorageError):
    """A uniquely indexed resource already exists."""


DEVICE_SELECT = """
    SELECT devices.*, ARRAY(
        SELECT host(address) FROM device_syslog_sources
        WHERE device_id = devices.device_id ORDER BY address
    ) AS source_addresses,
           host(management_ip) AS management_ip
    FROM devices
"""
EVENT_REFERENCES = """
    SELECT event_id, aggregate_id FROM alert_event_refs
    UNION
    SELECT event_id, aggregate_id FROM ospf_incident_event_refs WHERE is_current
    UNION
    SELECT event_id, aggregate_id FROM interface_link_recoveries
"""


def audit(
    connection: Any,
    action: str,
    resource_type: str,
    resource_id: str | None,
    actor: str | None,
    *,
    outcome: Literal["success", "failure"] = "success",
    metadata: dict[str, object] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO application_audit
            (action, resource_type, resource_id, actor_id, request_id, outcome, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            action,
            resource_type,
            resource_id,
            actor,
            request_id.get(),
            outcome,
            Jsonb(metadata or {}),
        ),
    )


def _device[T: DeviceRecord](row: dict[str, Any], now: datetime, model: type[T]) -> T:
    row["status"] = device_status(
        row["enabled"], row["last_seen"], row["expected_interval_seconds"], now
    )
    return model.model_validate(row)


def event_where(
    filters: EventFilters,
    *,
    time_column: Literal["event_timestamp", "ingested_at"] | None = "event_timestamp",
) -> tuple[str, list[Any]]:
    predicates: list[str] = []
    values: list[Any] = []
    if time_column:
        predicates.append(f"{time_column} >= %s AND {time_column} < %s")
        values.extend([filters.start, filters.end])
    for column, value in (
        ("device_id", filters.device_id),
        ("device_name", filters.device_name),
        ("severity", filters.severity),
        ("category", filters.category),
        ("event_type", filters.event_type),
        ("vendor", filters.vendor),
    ):
        if value is not None:
            predicates.append(f"{column} = %s")
            values.append(value)
    if filters.search is not None:
        predicates.append("strpos(lower(message), lower(%s)) > 0")
        values.append(filters.search)
    return " AND ".join(predicates) or "true", values


def _incident_where(filters: EventFilters) -> tuple[str, list[Any]]:
    predicates = [VISIBLE_ALERT]
    arguments: list[Any] = []
    if filters.severity:
        predicates.append("severity = %s")
        arguments.append(filters.severity.value)
    if filters.category:
        types = [
            kind.value for kind, category in CATEGORIES.items() if category == filters.category
        ]
        predicates.append("event_types ?| %s")
        arguments.append(types)
    if filters.event_type:
        predicates.append("event_types ? %s")
        arguments.append(filters.event_type.value)
    match: list[str] = []
    for column, value in (
        ("device_id", filters.device_id),
        ("device_name", filters.device_name),
        ("vendor", filters.vendor),
    ):
        if value is not None:
            match.append(f"catalog.{column} = %s")
            arguments.append(value)
    if filters.search:
        match.append("strpos(lower(catalog.message), lower(%s)) > 0")
        arguments.append(filters.search)
    if match:
        matching = " AND ".join(match)
        predicates.append(
            f"""EXISTS (SELECT 1 FROM ({EVENT_REFERENCES}) AS ref
                        JOIN event_catalog AS catalog USING (event_id)
                        WHERE ref.aggregate_id = aggregated_alerts.aggregate_id AND {matching})"""
        )
        if filters.device_name and not (filters.device_id or filters.vendor or filters.search):
            predicates[-1] = f"({predicates[-1]} OR device_name = %s)"
            arguments.append(filters.device_name)
    return " AND ".join(predicates), arguments


class PostgresBackendStorage(PostgresAlertStorage):
    def record_event(
        self,
        event: NormalizedEvent,
        collector_source: str | None,
        priority: int | None,
        raw_prefix: bool,
        ospf: OspfCorrelationConfig | None,
        use_managed_rules: bool = False,
        *,
        alert: AggregatedAlert | None = None,
        ospf_snapshot: OspfCorrelationSnapshot | None = None,
    ) -> None:
        address = transport_address(collector_source)
        with self._connect() as connection:
            if alert is not None:
                self.upsert_alert(alert, event, transaction=connection)
            if ospf_snapshot is not None:
                self.apply_ospf_snapshot(ospf_snapshot, transaction=connection)
            inserted = connection.execute(
                """
                INSERT INTO event_catalog
                    (event_id, event_timestamp, received_at, device_id, device_name, collector_ip,
                     source_ip, vendor, severity, event_type, category, message, parser_name,
                     syslog_priority, raw_prefix)
                VALUES (%s, %s, %s,
                    (SELECT device_id FROM device_syslog_sources JOIN devices USING (device_id)
                     WHERE address = %s AND enabled AND (vendor IS NULL OR vendor = %s)),
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING RETURNING device_id
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.received_at,
                    address,
                    event.vendor.value,
                    event.device_name,
                    address,
                    event.source_ip,
                    event.vendor.value,
                    event.severity.value,
                    event.event_type.value,
                    CATEGORIES[event.event_type].value,
                    redact(event.message),
                    event.parser_name,
                    priority,
                    raw_prefix,
                ),
            ).fetchone()
            if inserted is None:
                return
            if inserted["device_id"]:
                connection.execute(
                    "UPDATE devices SET last_seen = GREATEST(last_seen, %s) WHERE device_id = %s",
                    (event.received_at, inserted["device_id"]),
                )
            if ospf and ospf.enabled and event.current_state is not None:
                self._record_observation(connection, event, ospf, address)
            identity = None
            if inserted["device_id"]:
                identity = str(inserted["device_id"])
            elif address and event.device_name:
                identity = f"{address}/{event.vendor.value}/{event.device_name}"
            if use_managed_rules:
                correlate_event(connection, event, identity)
            else:
                record_interface_observation(connection, event, identity)

    def rules(self) -> list[RuleRecord]:
        with self._connect() as connection:
            return rule_records(connection)

    def update_rule(
        self,
        body: RuleCreate | RulePatch,
        config: CorrelationConfig,
        rule_id: str,
        actor: str,
    ) -> RuleRecord | None:
        with self._connect() as connection:
            record, prior = save_rule(connection, body, config, rule_id)
            if record is not None:
                action = "rule.create" if prior is None else "rule.update"
                if prior is not None and prior.enabled != record.enabled:
                    action = "rule.enable" if record.enabled else "rule.disable"
                audit(
                    connection,
                    action,
                    "rule",
                    rule_id,
                    actor,
                    metadata={"revision": record.revision, "enabled": record.enabled},
                )
            return record

    @staticmethod
    def _record_observation(
        connection: Any,
        event: NormalizedEvent,
        ospf: OspfCorrelationConfig,
        collector_source: str | None,
    ) -> None:
        try:
            identity = resolve_ospf_identity(event, ospf, collector_source)
        except ValueError:
            identity = None
        adjacency = identity.adjacency if identity else None
        reliable = abs(event.timestamp - event.received_at) <= timedelta(
            seconds=ospf.max_clock_skew_seconds
        )
        connection.execute(
            """
            INSERT INTO ospf_link_observations
                (event_id, adjacency_id, link_id, scope, area, device_name, interface_name,
                 local_router_id, peer_router_id, state, observed_at, reliable)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.event_id,
                ospf_adjacency_id(adjacency) if adjacency else None,
                adjacency.link_id if adjacency else None,
                ospf.scope,
                adjacency.area if adjacency else event.ospf_area,
                event.device_name,
                event.interface_name,
                identity.reporter if identity else event.local_router_id,
                event.neighbor_router_id,
                event.current_state,
                event.timestamp if reliable else event.received_at,
                reliable,
            ),
        )

    def device(self, device_id: UUID) -> DeviceRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                f"{DEVICE_SELECT} WHERE device_id = %s", (device_id,)
            ).fetchone()
            return _device(row, datetime.now(UTC), DeviceRecord) if row else None

    def devices(
        self, page: int, size: int, search: str | None = None, enabled: bool | None = None
    ) -> Page[DeviceRecord]:
        conditions = ["true"]
        arguments: list[Any] = []
        if search is not None:
            conditions.append(
                "strpos(lower(concat_ws(' ', name, hostname, location)), lower(%s)) > 0"
            )
            arguments.append(search)
        if enabled is not None:
            conditions.append("enabled = %s")
            arguments.append(enabled)
        where = " AND ".join(conditions)
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = connection.execute(
                f"{DEVICE_SELECT} WHERE {where} ORDER BY lower(name), device_id LIMIT %s OFFSET %s",
                (*arguments, size, (page - 1) * size),
            ).fetchall()
            count = connection.execute(
                f"SELECT count(*) AS total FROM devices WHERE {where}", arguments
            )
            now = datetime.now(UTC)
            return Page[DeviceRecord](
                items=[_device(row, now, DeviceRecord) for row in rows],
                page=page,
                page_size=size,
                total=count.fetchone()["total"],
            )

    def device_activity(
        self,
        filters: EventFilters,
        page: int,
        size: int,
        enabled: bool | None = None,
    ) -> Page[DeviceActivity]:
        events, event_args = event_where(replace(filters, device_id=None, device_name=None))
        where = """
            (%s::uuid IS NULL OR devices.device_id = %s)
            AND (%s::text IS NULL OR lower(name) = lower(%s))
            AND (%s::boolean IS NULL OR enabled = %s)
        """
        args = (
            filters.device_id,
            filters.device_id,
            filters.device_name,
            filters.device_name,
            enabled,
            enabled,
        )
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = connection.execute(
                f"""SELECT page.*, activity.* FROM (
                      {DEVICE_SELECT} WHERE {where}
                      ORDER BY lower(name), device_id LIMIT %s OFFSET %s
                    ) AS page
                    CROSS JOIN LATERAL (
                        SELECT count(*) AS event_count, min(event_timestamp) AS first_event_at,
                               max(event_timestamp) AS last_event_at FROM event_catalog
                        WHERE event_catalog.device_id = page.device_id AND {events}
                    ) AS activity
                    ORDER BY lower(page.name), page.device_id""",
                (*args, size, (page - 1) * size, *event_args),
            ).fetchall()
            total = connection.execute(
                f"SELECT count(*) AS total FROM devices WHERE {where}", args
            ).fetchone()["total"]
            now = datetime.now(UTC)
            return Page[DeviceActivity](
                items=[_device(row, now, DeviceActivity) for row in rows],
                page=page,
                page_size=size,
                total=total,
            )

    def save_device(
        self, body: DeviceCreate | DevicePatch, actor: str, device_id: UUID | None = None
    ) -> DeviceRecord | None:
        try:
            with self._connect() as connection:
                original = None
                if device_id is not None:
                    original = connection.execute(
                        f"{DEVICE_SELECT} WHERE device_id = %s FOR UPDATE", (device_id,)
                    ).fetchone()
                    if original is None:
                        return None
                changes = body.model_dump(exclude_unset=isinstance(body, DevicePatch))
                fields = DeviceCreate.model_fields
                if original is None:
                    device_id = uuid4()
                    device = DeviceCreate.model_validate(changes)
                    action = "device.create"
                else:
                    device = DeviceCreate.model_validate(
                        {**{key: original[key] for key in fields}, **changes}
                    )
                    action = (
                        "device.deactivate"
                        if original["enabled"] and not device.enabled
                        else "device.update"
                    )
                values = device.model_dump(exclude={"source_addresses"})
                columns = ", ".join(values)
                placeholders = ", ".join("%s" for _ in values)
                assignments = ", ".join(f"{key} = EXCLUDED.{key}" for key in values)
                connection.execute(
                    f"""INSERT INTO devices (device_id, {columns}) VALUES (%s, {placeholders})
                        ON CONFLICT (device_id) DO UPDATE SET {assignments}, updated_at = now()""",
                    (device_id, *values.values()),
                )
                if original is None or "source_addresses" in changes:
                    connection.execute(
                        "DELETE FROM device_syslog_sources WHERE device_id = %s", (device_id,)
                    )
                    for address in sorted(device.source_addresses, key=str):
                        connection.execute(
                            "INSERT INTO device_syslog_sources (address, device_id) "
                            "VALUES (%s, %s)",
                            (address, device_id),
                        )
                audit(
                    connection,
                    action,
                    "device",
                    str(device_id),
                    actor,
                    metadata={"fields": sorted(changes)},
                )
                row = connection.execute(
                    f"{DEVICE_SELECT} WHERE device_id = %s", (device_id,)
                ).fetchone()
                return _device(row, datetime.now(UTC), DeviceRecord)
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise DuplicateResource(
                    "Device name, hostname or address is already registered"
                ) from exc
            raise

    def event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM event_catalog WHERE event_id = %s", (event_id,)
            ).fetchone()
            return row

    def events(
        self,
        filters: EventFilters,
        page: int,
        size: int,
        order: Literal["asc", "desc"] = "desc",
    ) -> Page[IndexedEvent]:
        where, arguments = event_where(filters)
        direction = "ASC" if order == "asc" else "DESC"
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = connection.execute(
                f"""SELECT * FROM event_catalog WHERE {where}
                    ORDER BY event_timestamp {direction}, event_id {direction}
                    LIMIT %s OFFSET %s""",
                (*arguments, size, (page - 1) * size),
            ).fetchall()
            total = connection.execute(
                f"SELECT count(*) AS total FROM event_catalog WHERE {where}", arguments
            ).fetchone()["total"]
            return Page[IndexedEvent](
                items=[IndexedEvent.model_validate(row) for row in rows],
                page=page,
                page_size=size,
                total=total,
            )

    def relations(self, event_id: str, limit: int = 50) -> EventRelations:
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                WITH refs AS NOT MATERIALIZED ({EVENT_REFERENCES}), incident_ids AS (
                    SELECT aggregate_id FROM refs JOIN aggregated_alerts USING (aggregate_id)
                    WHERE event_id = %s AND {VISIBLE_ALERT} ORDER BY aggregate_id LIMIT %s
                )
                SELECT ARRAY(SELECT aggregate_id FROM incident_ids) AS incident_ids,
                       ARRAY(SELECT DISTINCT event_id FROM refs
                             JOIN incident_ids USING (aggregate_id)
                             WHERE event_id <> %s ORDER BY event_id LIMIT %s) AS related_event_ids
                """,
                (event_id, limit, event_id, limit),
            ).fetchone()
            return EventRelations.model_validate(rows)

    def incidents(
        self, filters: EventFilters, page: int, size: int, *, ospf_only: bool = False
    ) -> Page[AlertRecord]:
        where, arguments = _incident_where(filters)
        where += " AND first_seen < %s AND last_seen >= %s"
        arguments.extend([filters.end, filters.start])
        if ospf_only:
            where += """ AND EXISTS (SELECT 1 FROM ospf_incidents AS ospf
                                     WHERE ospf.aggregate_id = aggregated_alerts.aggregate_id)"""
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = connection.execute(
                f"""SELECT * FROM aggregated_alerts WHERE {where}
                    ORDER BY last_seen DESC, aggregate_id DESC LIMIT %s OFFSET %s""",
                (*arguments, size, (page - 1) * size),
            ).fetchall()
            total = connection.execute(
                f"SELECT count(*) AS total FROM aggregated_alerts WHERE {where}", arguments
            ).fetchone()["total"]
            return Page[AlertRecord](
                items=[_record(row) for row in rows], page=page, page_size=size, total=total
            )

    def audit_event(
        self,
        action: str,
        resource_type: str,
        resource_id: str | None,
        actor: str | None,
        *,
        outcome: Literal["success", "failure"] = "success",
    ) -> None:
        with self._connect() as connection:
            audit(connection, action, resource_type, resource_id, actor, outcome=outcome)

    def audit_log(
        self,
        page: int,
        size: int,
        start: datetime,
        end: datetime,
        action: str | None,
        actor: str | None,
        outcome: str | None,
    ) -> Page[AuditRecord]:
        conditions = ["timestamp >= %s AND timestamp < %s"]
        arguments: list[Any] = [start, end]
        for column, value in (("action", action), ("actor_id", actor), ("outcome", outcome)):
            if value is not None:
                conditions.append(f"{column} = %s")
                arguments.append(value)
        where = " AND ".join(conditions)
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = connection.execute(
                f"""SELECT * FROM application_audit WHERE {where}
                    ORDER BY timestamp DESC, audit_id DESC LIMIT %s OFFSET %s""",
                (*arguments, size, (page - 1) * size),
            ).fetchall()
            total = connection.execute(
                f"SELECT count(*) AS total FROM application_audit WHERE {where}", arguments
            ).fetchone()["total"]
            return Page[AuditRecord](
                items=[AuditRecord.model_validate(row) for row in rows],
                page=page,
                page_size=size,
                total=total,
            )

    def summary(self, filters: EventFilters) -> dict[str, Any]:
        where, args = event_where(filters)
        ingestion_where, ingestion_args = event_where(filters, time_column="ingested_at")
        latest_where, latest_args = event_where(filters, time_column=None)
        incident_where, incident_args = _incident_where(filters)
        bucket = "hour" if filters.end - filters.start <= timedelta(days=3) else "day"
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '10s'")
            grouped = connection.execute(
                f"""
                SELECT count(*) AS events, severity, category,
                       COALESCE(device_name, '(unknown)') AS source,
                       GROUPING(severity, category, device_name) AS dimension
                FROM event_catalog WHERE {where}
                GROUP BY GROUPING SETS ((), (severity), (category), (device_name))
                ORDER BY dimension DESC, events DESC, source
                """,
                args,
            ).fetchall()
            count = grouped[0]["events"]
            by_source = {row["source"]: row["events"] for row in grouped if row["dimension"] == 6}
            if len(by_source) > 100:
                sources = list(by_source.items())
                by_source = dict(sources[:100])
                by_source["(other sources)"] = sum(value for _, value in sources[100:])
            times = connection.execute(
                f"""
                SELECT (SELECT min(ingested_at) FROM event_catalog) AS coverage_start,
                       (SELECT max(ingested_at) FROM event_catalog WHERE {latest_where})
                       AS last_ingested_at
                """,
                latest_args,
            ).fetchone()
            trends = {}
            for key, column, conditions, values in (
                ("trend", "event_timestamp", where, args),
                ("ingestion_trend", "ingested_at", ingestion_where, ingestion_args),
            ):
                trends[key] = [
                    TrendPoint.model_validate(row)
                    for row in connection.execute(
                        f"""SELECT date_trunc(%s, {column}) AS timestamp, count(*) AS count
                            FROM event_catalog WHERE {conditions} GROUP BY 1 ORDER BY 1""",
                        (bucket, *values),
                    ).fetchall()
                ]
            incident = connection.execute(
                f"""
                WITH selected AS (
                    SELECT *, status = 'resolved' AND status_changed_at >= %s
                        AND status_changed_at < %s AS resolution_in_range
                    FROM aggregated_alerts WHERE first_seen < %s AND {incident_where}
                )
                SELECT count(*) FILTER (WHERE status <> 'resolved') AS active_incidents,
                       count(*) FILTER (WHERE resolution_in_range) AS resolved_incidents,
                       count(*) FILTER (WHERE severity = 'critical' AND
                           (status <> 'resolved' OR resolution_in_range)) AS critical_incidents,
                       count(*) FILTER (WHERE severity = 'high' AND
                           (status <> 'resolved' OR resolution_in_range)) AS high_incidents,
                       avg(EXTRACT(EPOCH FROM status_changed_at - first_seen))
                           FILTER (WHERE resolution_in_range AND status_changed_at >= first_seen)
                           AS mean_resolution_seconds
                FROM selected
                """,
                (filters.start, filters.end, filters.end, *incident_args),
            ).fetchone()
            devices = connection.execute(
                """
                SELECT status, count(*) AS count
                FROM kpi_device_facts
                WHERE (%s::uuid IS NULL OR device_id = %s)
                  AND (%s::text IS NULL OR lower(name) = lower(%s))
                GROUP BY 1
                """,
                (filters.device_id, filters.device_id, filters.device_name, filters.device_name),
            ).fetchall()
            significant = connection.execute(
                f"""SELECT * FROM event_catalog WHERE {where} AND severity IN ('critical', 'high')
                    ORDER BY event_timestamp DESC, event_id DESC LIMIT 10""",
                args,
            ).fetchall()
            return {
                "start": filters.start,
                "end": filters.end,
                **times,
                **incident,
                **trends,
                "total_events": count,
                "by_severity": {
                    row["severity"]: row["events"] for row in grouped if row["dimension"] == 3
                },
                "by_category": {
                    row["category"]: row["events"] for row in grouped if row["dimension"] == 5
                },
                "by_source": by_source,
                "registered_devices": sum(row["count"] for row in devices),
                "device_status": {row["status"]: row["count"] for row in devices},
                "significant_events": [IndexedEvent.model_validate(row) for row in significant],
                "events_per_second": sum(point.count for point in trends["ingestion_trend"])
                / (filters.end - filters.start).total_seconds(),
            }

    def topology_evidence(
        self,
        scope: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        with self._connect() as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '10s'")
            observations = connection.execute(
                """
                WITH ranked AS (
                    SELECT observed.*, catalog.device_id, host(catalog.collector_ip) AS collector,
                           max(observed_at) OVER endpoint AS last_observed_at,
                           row_number() OVER (
                               endpoint ORDER BY reliable DESC, observed_at DESC,
                                                 (state = 'DOWN') DESC, event_id DESC
                           ) AS rank
                    FROM ospf_link_observations AS observed
                    JOIN event_catalog AS catalog USING (event_id)
                    WHERE scope = %s
                    WINDOW endpoint AS (
                        PARTITION BY link_id, observed.device_name, interface_name, area,
                                     local_router_id, peer_router_id,
                                     CASE WHEN link_id IS NULL THEN catalog.device_id END,
                                     CASE WHEN link_id IS NULL THEN catalog.collector_ip END
                    )
                )
                SELECT event_id, adjacency_id, link_id, scope, host(area) AS area, device_name,
                       interface_name, host(local_router_id) AS local_router_id,
                       host(peer_router_id) AS peer_router_id, state, last_observed_at, reliable,
                       device_id, collector
                FROM ranked WHERE rank = 1
                ORDER BY last_observed_at DESC, event_id DESC LIMIT 1001
                """,
                (scope,),
            ).fetchall()
            incidents = connection.execute(
                """
                SELECT adjacency_key, incident.adjacency_id,
                       bool_or(technical_recovered_at IS NULL) AS has_outage,
                       (array_agg(incident.aggregate_id ORDER BY alert.last_seen DESC))[1:20] AS ids
                FROM ospf_incidents AS incident
                JOIN ospf_adjacencies USING (adjacency_id)
                JOIN aggregated_alerts AS alert USING (aggregate_id)
                WHERE superseded_at IS NULL AND adjacency_key->>'scope' = %s
                GROUP BY adjacency_key, incident.adjacency_id
                ORDER BY max(alert.last_seen) DESC LIMIT 1001
                """,
                (scope,),
            ).fetchall()
            counts = connection.execute(
                f"""
                WITH membership AS (
                    SELECT device_id, aggregate_id FROM ({EVENT_REFERENCES}) AS ref
                    JOIN event_catalog USING (event_id) WHERE device_id IS NOT NULL
                    UNION
                    SELECT device_id, incident.aggregate_id
                    FROM ospf_incidents AS incident JOIN ospf_adjacencies USING (adjacency_id)
                    JOIN ospf_link_observations AS observation USING (adjacency_id)
                    JOIN event_catalog USING (event_id) WHERE device_id IS NOT NULL
                )
                SELECT device_id, severity, count(*) AS incidents FROM membership
                JOIN aggregated_alerts USING (aggregate_id)
                WHERE status <> 'resolved' AND {VISIBLE_ALERT}
                GROUP BY device_id, severity
                """,
            ).fetchall()
            return observations, incidents, counts
