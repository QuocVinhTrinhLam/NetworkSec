"""Transactional storage and execution for managed correlation rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg.types.json import Jsonb

from app.schemas.correlation import CorrelationConfig
from app.schemas.event import NormalizedEvent
from app.services.managed_rules import RuleCreate, RuleMatch, RulePatch, RuleRecord, match_rule
from app.storage.base import StorageError

MAX_RULES = 128


class RuleConflict(StorageError):
    """Rule change conflicts with deployed built-in policy or registry limits."""


def rule_records(connection: Any) -> list[RuleRecord]:
    rows = connection.execute(
        "SELECT id, revision, enabled, definition FROM managed_rules ORDER BY id"
    ).fetchall()
    return [RuleRecord.model_validate(row) for row in rows]


def save_rule(
    connection: Any, body: RuleCreate | RulePatch, config: CorrelationConfig, rule_id: str
) -> tuple[RuleRecord | None, RuleRecord | None]:
    # Serialize rule changes, including the fixed registry limit.
    connection.execute("SELECT pg_advisory_xact_lock(hashtext('networksec-managed-rules'))")
    if rule_id in {rule.id for rule in config.rules} or rule_id in {"ospf", "ospf-adjacency"}:
        raise RuleConflict("The built-in rule is managed in the correlation configuration")
    old = connection.execute(
        "SELECT id, revision, enabled, definition FROM managed_rules WHERE id = %s", (rule_id,)
    ).fetchone()
    prior = RuleRecord.model_validate(old) if old else None
    if isinstance(body, RuleCreate):
        if prior is not None:
            raise RuleConflict("Rule already exists")
        if (
            connection.execute("SELECT count(*) AS n FROM managed_rules").fetchone()["n"]
            >= MAX_RULES
        ):
            raise RuleConflict("Managed rule limit reached")
        current = RuleRecord.model_validate({**body.model_dump(), "revision": 1})
    else:
        if prior is None:
            return None, None
        definition = body.definition or prior.definition
        current = RuleRecord(
            id=rule_id,
            definition=definition,
            enabled=body.enabled if body.enabled is not None else prior.enabled,
            revision=prior.revision + int(definition != prior.definition),
        )
    if current.enabled and (problem := current.definition.activation_error(config)):
        raise RuleConflict(problem)
    connection.execute(
        """
        INSERT INTO managed_rules (id, revision, enabled, definition) VALUES (%s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision, enabled = EXCLUDED.enabled,
          definition = EXCLUDED.definition, updated_at = now()
        """,
        (
            rule_id,
            current.revision,
            current.enabled,
            Jsonb(current.definition.model_dump(mode="json")),
        ),
    )
    return current, prior


def correlate_event(connection: Any, event: NormalizedEvent, identity: str | None) -> None:
    rows = connection.execute(
        """
        SELECT id, revision, enabled, definition FROM managed_rules
        WHERE enabled AND ((definition->'event_types') ? %s OR (definition->'recovery_types') ? %s)
        ORDER BY COALESCE((definition->>'priority')::integer, 100), id
        """,
        (event.event_type, event.event_type),
    ).fetchall()
    for row in rows:
        rule = RuleRecord.model_validate(row)
        if match := match_rule(rule, event, identity):
            _record_match(connection, rule, match, event)
            return


def _record_match(
    connection: Any, rule: RuleRecord, match: RuleMatch, event: NormalizedEvent
) -> None:
    definition = rule.definition
    connection.execute(
        """
        INSERT INTO rule_windows (aggregate_id, recovery_at) VALUES (%s, %s)
        ON CONFLICT (aggregate_id) DO UPDATE SET recovery_at =
            GREATEST(rule_windows.recovery_at, EXCLUDED.recovery_at)
        """,
        (match.aggregate_id, event.timestamp if match.recovery else None),
    )
    connection.execute(
        """
        INSERT INTO rule_window_events (event_id, aggregate_id, dedup_key, recovered)
        VALUES (%s, %s, %s, %s)
        """,
        (event.event_id, match.aggregate_id, match.dedup_key, match.recovery),
    )
    stats = connection.execute(
        """
        SELECT count(DISTINCT dedup_key) AS count, min(event_timestamp) AS first_seen,
               max(event_timestamp) AS last_seen, array_agg(DISTINCT event_type ORDER BY event_type)
               AS event_types
        FROM rule_window_events JOIN event_catalog USING (event_id)
        WHERE aggregate_id = %s AND NOT recovered
        """,
        (match.aggregate_id,),
    ).fetchone()
    if stats["count"] < definition.threshold:
        return
    connection.execute(
        """
        INSERT INTO aggregated_alerts (
            aggregate_id, schema_version, rule_id, event_family, group_key, device_name,
            interface_name, event_types, window_start, window_end, event_count,
            first_seen, last_seen,
            severity, notification_cooldown_seconds, status_changed_at, created_at, updated_at
        ) VALUES (%s, '1.0', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                  now(), now(), now())
        ON CONFLICT (aggregate_id) DO UPDATE SET
            event_types = EXCLUDED.event_types, event_count = EXCLUDED.event_count,
            first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen, updated_at = now()
        """,
        (
            match.aggregate_id,
            rule.id,
            definition.category,
            Jsonb(match.group),
            event.device_name,
            event.interface_name if "interface_name" in match.group else None,
            Jsonb(stats["event_types"]),
            match.start,
            match.end,
            stats["count"],
            stats["first_seen"],
            stats["last_seen"],
            definition.severity,
            definition.window_seconds,
        ),
    )
    connection.execute(
        """
        INSERT INTO alert_event_refs
            (event_id, aggregate_id, event_timestamp, source_ip, event_type)
        SELECT event_id, aggregate_id, event_timestamp, source_ip, event_type
        FROM rule_window_events JOIN event_catalog USING (event_id)
        WHERE aggregate_id = %s
        ON CONFLICT (event_id) DO NOTHING
        """,
        (match.aggregate_id,),
    )
    _recover(connection, match.aggregate_id, stats["last_seen"])


def _recover(connection: Any, aggregate_id: str, last_failure: datetime) -> None:
    # Rows are serialized by the rule_windows upsert. Operator resolutions take precedence.
    connection.execute(
        """
        WITH changed AS (
            UPDATE aggregated_alerts AS alert SET
                status = CASE WHEN slot.recovery_at > %s THEN 'resolved' ELSE COALESCE((
                    SELECT previous_status FROM alert_status_history AS history
                    WHERE history.aggregate_id = alert.aggregate_id AND status = 'resolved'
                      AND source IN ('rule_recovery', 'system')
                    ORDER BY change_id DESC LIMIT 1
                ), 'new') END,
                status_changed_at = now(),
                status_change_source = CASE WHEN slot.recovery_at > %s
                    THEN 'rule_recovery' ELSE 'rule_reassessment' END,
                status_changed_by = 'managed-rule', updated_at = now()
            FROM rule_windows AS slot
            WHERE alert.aggregate_id = slot.aggregate_id AND alert.aggregate_id = %s
            AND (
                (alert.status <> 'resolved' AND slot.recovery_at > %s)
                OR (alert.status = 'resolved'
                    AND alert.status_change_source IN ('rule_recovery', 'system')
                    AND slot.managed_recovery_at IS NOT NULL AND slot.recovery_at <= %s)
            )
            RETURNING alert.aggregate_id, alert.status
        )
        UPDATE rule_windows AS slot SET
            managed_recovery_at = CASE WHEN changed.status = 'resolved' THEN slot.recovery_at END
        FROM changed WHERE slot.aggregate_id = changed.aggregate_id
        """,
        (last_failure, last_failure, aggregate_id, last_failure, last_failure),
    )
