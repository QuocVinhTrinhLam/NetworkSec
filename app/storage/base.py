"""Typed boundaries shared by storage adapters and the HTTP API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Protocol

from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import (
    AggregatedAlert,
    OspfAdjacencyKey,
    OspfCorrelationSnapshot,
    OspfReporterState,
)
from app.schemas.event import (
    EventSchemaVersion,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)


class StorageError(RuntimeError):
    """A storage response could not be validated or completed."""


class StorageUnavailableError(StorageError):
    """A configured storage backend is temporarily unreachable."""


class InvalidCursorError(StorageError):
    """An opaque client pagination cursor is invalid or corrupted."""


@dataclass(frozen=True, slots=True)
class EventQuery:
    start: datetime
    end: datetime
    limit: int
    cursor: str | None = None
    severity: EventSeverity | None = None
    event_type: EventType | None = None
    vendor: EventVendor | None = None
    device_name: str | None = None
    interface_name: str | None = None
    schema_version: EventSchemaVersion | None = None
    event_id: str | None = None


@dataclass(frozen=True, slots=True)
class EventPage:
    items: tuple[NormalizedEvent, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class AlertQuery:
    start: datetime
    end: datetime
    page: int
    page_size: int
    severity: EventSeverity | None = None
    status: str | None = None
    event_type: EventType | None = None
    device_name: str | None = None
    interface_name: str | None = None
    include_active_before_start: bool = False
    rule_id: str | None = None
    source_ip: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class AlertListMetadata:
    adjacency: OspfAdjacencyKey | None = None
    source_ips: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AlertPage:
    items: tuple[AlertRecord, ...]
    total: int
    metadata: dict[str, AlertListMetadata] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AlertQueueSummary:
    new: int
    acknowledged: int
    high_priority: int
    recently_resolved: int


@dataclass(frozen=True, slots=True)
class AlertStatusChange:
    previous_status: AlertLifecycleStatus | None
    status: AlertLifecycleStatus
    source: str
    actor: str | None
    note: str | None
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class IncidentEventRef:
    event_id: str
    timestamp: datetime
    reporter_router_id: IPv4Address | None = None
    event_type: EventType | None = None
    is_current: bool = True
    source_ip: str | None = None


@dataclass(frozen=True, slots=True)
class OspfIncidentRecord:
    adjacency: OspfAdjacencyKey
    technical_recovered_at: datetime | None
    superseded_at: datetime | None
    reporters: tuple[OspfReporterState, ...]
    event_refs: tuple[IncidentEventRef, ...]


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    alert: AlertRecord
    event_refs: tuple[IncidentEventRef, ...]
    history: tuple[AlertStatusChange, ...]
    ospf: OspfIncidentRecord | None = None


class LogStorage(Protocol):
    async def push_event(self, event: NormalizedEvent) -> None: ...

    async def query_events(self, query: EventQuery) -> EventPage: ...

    async def ready(self) -> bool: ...


class AlertStateStorage(Protocol):
    def migrate(self) -> None: ...

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord: ...

    def apply_ospf_snapshot(self, snapshot: OspfCorrelationSnapshot) -> bool: ...

    def query_alerts(self, query: AlertQuery) -> AlertPage: ...

    def get_alert(self, aggregate_id: str) -> AlertRecord | None: ...

    def get_alert_evidence(self, aggregate_id: str) -> AlertEvidence | None: ...

    def queue_summary(self, start: datetime, end: datetime) -> AlertQueueSummary: ...

    def acknowledge(
        self, aggregate_id: str, actor: str, note: str | None
    ) -> AlertRecord | None: ...

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None: ...

    def dashboard_stats(self, start: datetime, end: datetime) -> dict[str, Any]: ...

    def claim_notifications(
        self, minimum_severity: EventSeverity, now: datetime, limit: int = 100
    ) -> tuple[AlertRecord, ...]: ...

    def get_telegram_message_id(self, aggregate_id: str, chat_id: int) -> int | None: ...

    def save_telegram_message_id(
        self, aggregate_id: str, chat_id: int, message_id: int
    ) -> None: ...

    def ready(self) -> bool: ...
