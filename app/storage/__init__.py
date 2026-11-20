"""Storage adapters for Phase 5 log and alert persistence."""

from app.storage.base import (
    AlertPage,
    AlertQuery,
    AlertStateStorage,
    EventPage,
    EventQuery,
    InvalidCursorError,
    LogStorage,
    StorageError,
    StorageUnavailableError,
)
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage

__all__ = [
    "AlertPage",
    "AlertQuery",
    "AlertStateStorage",
    "EventPage",
    "EventQuery",
    "InvalidCursorError",
    "LogStorage",
    "LokiLogStorage",
    "PostgresAlertStorage",
    "StorageError",
    "StorageUnavailableError",
]
