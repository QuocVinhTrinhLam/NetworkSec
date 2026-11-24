"""SQLite-backed, replay-safe correlation for normalized network events."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.schemas.correlation import (
    AggregatedAlert,
    CorrelatedRawEvent,
    CorrelationConfig,
    CorrelationResult,
    CorrelationRule,
    NotificationClaim,
    OspfAdjacencyKey,
    OspfCorrelationSnapshot,
)
from app.schemas.event import EventSeverity, EventType, NormalizedEvent, OspfNeighborState
from app.services.ospf_correlation import (
    OspfIdentity,
    OspfObservation,
    project_ospf,
    resolve_ospf_identity,
)

CORRELATION_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS correlation_alerts (
    aggregate_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_family TEXT NOT NULL,
    group_key_json TEXT NOT NULL,
    device_name TEXT,
    interface_name TEXT,
    event_types_json TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    event_count INTEGER NOT NULL CHECK(event_count >= 1),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    severity TEXT NOT NULL,
    notification_cooldown_seconds INTEGER NOT NULL,
    last_notification_at TEXT,
    notification_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_correlation_alerts_window
    ON correlation_alerts(rule_id, window_start, window_end);

CREATE TABLE IF NOT EXISTS correlation_events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    normalized_event_json TEXT NOT NULL,
    persisted_at TEXT NOT NULL,
    FOREIGN KEY(aggregate_id) REFERENCES correlation_alerts(aggregate_id)
);

CREATE INDEX IF NOT EXISTS idx_correlation_events_aggregate
    ON correlation_events(aggregate_id, event_timestamp, event_id);

CREATE TABLE IF NOT EXISTS ospf_observations (
    sequence INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    event_id TEXT NOT NULL,
    adjacency_key TEXT NOT NULL,
    reporter_id TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('DOWN', 'FULL')),
    clock_reliable INTEGER NOT NULL CHECK(clock_reliable IN (0, 1)),
    uncertain_until TEXT,
    UNIQUE(scope, event_id)
);

CREATE INDEX IF NOT EXISTS idx_ospf_observations_adjacency
    ON ospf_observations(adjacency_key, sequence);
"""

OSPF_EVENT_TYPES = frozenset(
    (
        EventType.ROUTING_NEIGHBOR_DOWN,
        EventType.ROUTING_NEIGHBOR_UP,
        EventType.ROUTING_NEIGHBOR_STATE_CHANGE,
    )
)

SEVERITY_RANK = {
    EventSeverity.LOW: 0,
    EventSeverity.MEDIUM: 1,
    EventSeverity.HIGH: 2,
    EventSeverity.CRITICAL: 3,
}


class CorrelationConfigurationError(ValueError):
    """Raised when correlation YAML is unreadable or violates the contract."""


def load_correlation_config(path: Path) -> CorrelationConfig:
    """Safely load and validate a versioned correlation rules file."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CorrelationConfigurationError(f"cannot load correlation config: {exc}") from exc
    if not isinstance(document, dict):
        raise CorrelationConfigurationError("correlation config must be a YAML mapping")
    try:
        return CorrelationConfig.model_validate(document)
    except ValidationError as exc:
        raise CorrelationConfigurationError(f"invalid correlation config: {exc}") from exc


class CorrelationStore:
    """Transactional persistence for aggregate state and raw trace membership."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(CORRELATION_SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def persist(self, event: NormalizedEvent, rule: CorrelationRule) -> CorrelationResult:
        window_start, window_end = _event_window(event.timestamp, rule.window_seconds)
        group_key = _group_key(event, rule)
        aggregate_id = _aggregate_id(rule.id, group_key, window_start)
        now = datetime.now(UTC).isoformat()

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_event = connection.execute(
                "SELECT aggregate_id FROM correlation_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing_event is not None:
                alert = self._get_alert(connection, str(existing_event["aggregate_id"]))
                return CorrelationResult(matched=True, duplicate=True, alert=alert)

            existing_alert = connection.execute(
                "SELECT * FROM correlation_alerts WHERE aggregate_id = ?", (aggregate_id,)
            ).fetchone()
            if existing_alert is None:
                connection.execute(
                    """
                    INSERT INTO correlation_alerts (
                        aggregate_id, schema_version, rule_id, event_family,
                        group_key_json, device_name, interface_name, event_types_json,
                        window_start, window_end, event_count, first_seen, last_seen,
                        severity, notification_cooldown_seconds, created_at, updated_at
                    ) VALUES (?, '1.0', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        aggregate_id,
                        rule.id,
                        rule.event_family,
                        _json(group_key),
                        event.device_name,
                        event.interface_name,
                        _json([event.event_type.value]),
                        window_start.isoformat(),
                        window_end.isoformat(),
                        event.timestamp.isoformat(),
                        event.timestamp.isoformat(),
                        event.severity.value,
                        rule.notification_cooldown_seconds,
                        now,
                        now,
                    ),
                )
            else:
                current_severity = EventSeverity(str(existing_alert["severity"]))
                severity = max(
                    (current_severity, event.severity), key=lambda item: SEVERITY_RANK[item]
                )
                event_types = set(json.loads(str(existing_alert["event_types_json"])))
                event_types.add(event.event_type.value)
                first_seen = min(_parse_time(existing_alert["first_seen"]), event.timestamp)
                last_seen = max(_parse_time(existing_alert["last_seen"]), event.timestamp)
                connection.execute(
                    """
                    UPDATE correlation_alerts SET
                        event_types_json = ?, event_count = event_count + 1,
                        first_seen = ?, last_seen = ?, severity = ?, updated_at = ?
                    WHERE aggregate_id = ?
                    """,
                    (
                        _json(sorted(event_types)),
                        first_seen.isoformat(),
                        last_seen.isoformat(),
                        severity.value,
                        now,
                        aggregate_id,
                    ),
                )

            connection.execute(
                """
                INSERT INTO correlation_events (
                    event_id, aggregate_id, event_timestamp, received_at, event_type,
                    severity, raw_message, normalized_event_json, persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    aggregate_id,
                    event.timestamp.isoformat(),
                    event.received_at.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.raw_message,
                    event.model_dump_json(),
                    now,
                ),
            )
            alert = self._get_alert(connection, aggregate_id)
        return CorrelationResult(matched=True, alert=alert)

    def get_alert(self, aggregate_id: str) -> AggregatedAlert | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM correlation_alerts WHERE aggregate_id = ?", (aggregate_id,)
            ).fetchone()
        return _alert_from_row(row) if row is not None else None

    def list_alerts(self) -> list[AggregatedAlert]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM correlation_alerts ORDER BY window_start, aggregate_id"
            ).fetchall()
        return [_alert_from_row(row) for row in rows]

    def trace_events(self, aggregate_id: str) -> list[CorrelatedRawEvent]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM correlation_events WHERE aggregate_id = ?
                ORDER BY event_timestamp, event_id
                """,
                (aggregate_id,),
            ).fetchall()
        return [_trace_from_row(row) for row in rows]

    def persist_ospf(
        self,
        event: NormalizedEvent,
        identity: OspfIdentity,
        *,
        max_clock_skew: timedelta,
    ) -> CorrelationResult:
        """Atomically journal an observation and return the current adjacency snapshot."""
        state = event.current_state
        if state is None or state not in (OspfNeighborState.DOWN, OspfNeighborState.FULL):
            raise ValueError("OSPF correlation requires a DOWN or FULL observation")
        clock_reliable = abs(event.timestamp - event.received_at) <= max_clock_skew
        uncertain_until = (
            event.received_at + max_clock_skew
            if not clock_reliable and state is OspfNeighborState.DOWN
            else None
        )
        adjacency = identity.adjacency
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT adjacency_key, clock_reliable FROM ospf_observations
                WHERE scope = ? AND event_id = ?
                """,
                (adjacency.scope, event.event_id),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO ospf_observations (
                        scope, event_id, adjacency_key, reporter_id, event_timestamp,
                        received_at, state, clock_reliable, uncertain_until
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        adjacency.scope,
                        event.event_id,
                        adjacency.model_dump_json(),
                        str(identity.reporter),
                        event.timestamp.isoformat(),
                        event.received_at.isoformat(),
                        state.value,
                        int(clock_reliable),
                        uncertain_until.isoformat() if uncertain_until is not None else None,
                    ),
                )
            else:
                adjacency = OspfAdjacencyKey.model_validate_json(existing["adjacency_key"])
                clock_reliable = bool(existing["clock_reliable"])
            snapshot = self._ospf_snapshot(connection, adjacency)
        return CorrelationResult(
            matched=True,
            duplicate=existing is not None,
            reason=None if clock_reliable else "unreliable OSPF event timestamp",
            ospf=snapshot,
        )

    def ospf_snapshot(self, adjacency: OspfAdjacencyKey) -> OspfCorrelationSnapshot:
        """Reconstruct the projection from the durable observation journal."""
        with self.connect() as connection:
            return self._ospf_snapshot(connection, adjacency)

    def list_ospf_adjacencies(self) -> tuple[OspfAdjacencyKey, ...]:
        """Discover journaled adjacencies for a downstream reconciliation pass."""
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT DISTINCT adjacency_key FROM ospf_observations ORDER BY adjacency_key"
            )
            return tuple(OspfAdjacencyKey.model_validate_json(row["adjacency_key"]) for row in rows)

    @staticmethod
    def _ospf_snapshot(
        connection: sqlite3.Connection, adjacency: OspfAdjacencyKey
    ) -> OspfCorrelationSnapshot:
        rows = connection.execute(
            """
            SELECT sequence, event_id, reporter_id, event_timestamp, received_at,
                   state, clock_reliable, uncertain_until
            FROM ospf_observations WHERE adjacency_key = ? ORDER BY sequence
            """,
            (adjacency.model_dump_json(),),
        )
        return project_ospf(
            adjacency,
            [
                OspfObservation(
                    sequence=int(row["sequence"]),
                    event_id=str(row["event_id"]),
                    reporter=IPv4Address(row["reporter_id"]),
                    timestamp=_parse_time(row["event_timestamp"]),
                    received_at=_parse_time(row["received_at"]),
                    state=OspfNeighborState(row["state"]),
                    clock_reliable=bool(row["clock_reliable"]),
                    uncertain_until=(
                        _parse_time(row["uncertain_until"]) if row["uncertain_until"] else None
                    ),
                )
                for row in rows
            ],
        )

    def claim_notification(self, aggregate_id: str, now: datetime) -> NotificationClaim:
        """Atomically claim notification eligibility while enforcing persisted cooldown."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("notification claim timestamp must be timezone-aware")
        observed_at = now.astimezone(UTC)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM correlation_alerts WHERE aggregate_id = ?", (aggregate_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown aggregate_id: {aggregate_id}")
            last_raw = row["last_notification_at"]
            cooldown = timedelta(seconds=int(row["notification_cooldown_seconds"]))
            last_notification = _parse_time(last_raw) if last_raw else None
            next_allowed = last_notification + cooldown if last_notification else None
            if next_allowed is not None and observed_at < next_allowed:
                return NotificationClaim(
                    allowed=False,
                    aggregate_id=aggregate_id,
                    next_allowed_at=next_allowed,
                )
            connection.execute(
                """
                UPDATE correlation_alerts SET
                    last_notification_at = ?, notification_count = notification_count + 1,
                    updated_at = ?
                WHERE aggregate_id = ?
                """,
                (observed_at.isoformat(), observed_at.isoformat(), aggregate_id),
            )
        return NotificationClaim(
            allowed=True,
            aggregate_id=aggregate_id,
            claimed_at=observed_at,
            next_allowed_at=observed_at + cooldown,
        )

    @staticmethod
    def _get_alert(connection: sqlite3.Connection, aggregate_id: str) -> AggregatedAlert:
        row = connection.execute(
            "SELECT * FROM correlation_alerts WHERE aggregate_id = ?", (aggregate_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("correlation alert disappeared inside transaction")
        return _alert_from_row(row)


class CorrelationEngine:
    """Match normalized events to configured rules and persist correlation state."""

    def __init__(self, store: CorrelationStore, config: CorrelationConfig) -> None:
        self.store = store
        self.config = config

    @classmethod
    def from_files(cls, database_path: Path, config_path: Path) -> CorrelationEngine:
        store = CorrelationStore(database_path)
        store.initialize()
        return cls(store, load_correlation_config(config_path))

    def process(
        self, event: NormalizedEvent, *, collector_source: str | None = None
    ) -> CorrelationResult:
        ospf = self.config.ospf
        if ospf is not None and ospf.enabled and event.event_type in OSPF_EVENT_TYPES:
            if event.current_state not in (OspfNeighborState.DOWN, OspfNeighborState.FULL):
                return CorrelationResult(matched=False, reason="no OSPF outage transition")
            try:
                identity = resolve_ospf_identity(event, ospf, collector_source)
            except ValueError as exc:
                return CorrelationResult(matched=False, reason=str(exc))
            return self.store.persist_ospf(
                event,
                identity,
                max_clock_skew=timedelta(seconds=ospf.max_clock_skew_seconds),
            )
        for rule in self.config.rules:
            if not rule.enabled or event.event_type not in rule.event_types:
                continue
            missing = [name for name in rule.required_fields if getattr(event, name) is None]
            if missing:
                return CorrelationResult(
                    matched=False,
                    reason=f"missing required correlation fields: {', '.join(missing)}",
                )
            return self.store.persist(event, rule)
        return CorrelationResult(matched=False, reason="no enabled correlation rule matched")


def _event_window(timestamp: datetime, window_seconds: int) -> tuple[datetime, datetime]:
    timestamp_utc = timestamp.astimezone(UTC)
    window_epoch = math.floor(timestamp_utc.timestamp() / window_seconds) * window_seconds
    start = datetime.fromtimestamp(window_epoch, UTC)
    return start, start + timedelta(seconds=window_seconds)


def _group_key(event: NormalizedEvent, rule: CorrelationRule) -> dict[str, str]:
    values = {
        "device_name": event.device_name or "",
        "interface_name": event.interface_name or "",
        "event_family": rule.event_family,
        "event_type": event.event_type.value,
    }
    return {field: values[field] for field in rule.group_by}


def _aggregate_id(rule_id: str, group_key: dict[str, str], window_start: datetime) -> str:
    identity = "\x1f".join((rule_id, _json(group_key), window_start.isoformat()))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _alert_from_row(row: sqlite3.Row) -> AggregatedAlert:
    return AggregatedAlert(
        aggregate_id=str(row["aggregate_id"]),
        rule_id=str(row["rule_id"]),
        event_family=str(row["event_family"]),
        group_key=json.loads(str(row["group_key_json"])),
        device_name=row["device_name"],
        interface_name=row["interface_name"],
        event_types=tuple(json.loads(str(row["event_types_json"]))),
        window_start=_parse_time(row["window_start"]),
        window_end=_parse_time(row["window_end"]),
        count=int(row["event_count"]),
        first_seen=_parse_time(row["first_seen"]),
        last_seen=_parse_time(row["last_seen"]),
        severity=EventSeverity(str(row["severity"])),
        notification_cooldown_seconds=int(row["notification_cooldown_seconds"]),
        last_notification_at=(
            _parse_time(row["last_notification_at"]) if row["last_notification_at"] else None
        ),
        notification_count=int(row["notification_count"]),
    )


def _trace_from_row(row: sqlite3.Row) -> CorrelatedRawEvent:
    return CorrelatedRawEvent(
        event_id=str(row["event_id"]),
        aggregate_id=str(row["aggregate_id"]),
        event_timestamp=_parse_time(row["event_timestamp"]),
        received_at=_parse_time(row["received_at"]),
        event_type=str(row["event_type"]),
        severity=str(row["severity"]),
        raw_message=str(row["raw_message"]),
        event=NormalizedEvent.model_validate_json(str(row["normalized_event_json"])),
    )


def _parse_time(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("stored correlation timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
