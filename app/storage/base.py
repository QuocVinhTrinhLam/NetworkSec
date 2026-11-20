"""Typed boundaries shared by storage adapters and the HTTP API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.schemas.api import AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import EventSeverity, EventType, EventVendor, NormalizedEvent


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


@dataclass(frozen=True, slots=True)
class AlertPage:
    items: tuple[AlertRecord, ...]
    total: int


class LogStorage(Protocol):
    async def push_event(self, event: NormalizedEvent) -> None: ...

    async def query_events(self, query: EventQuery) -> EventPage: ...

    async def ready(self) -> bool: ...


class AlertStateStorage(Protocol):
    def migrate(self) -> None: ...

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord: ...

    def query_alerts(self, query: AlertQuery) -> AlertPage: ...

    def get_alert(self, aggregate_id: str) -> AlertRecord | None: ...

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
