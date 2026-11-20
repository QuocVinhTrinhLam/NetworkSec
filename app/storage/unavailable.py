"""Explicit disabled backend used when PostgreSQL is not configured."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.api import AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import EventSeverity, NormalizedEvent
from app.storage.base import AlertPage, AlertQuery, StorageUnavailableError


class UnavailableAlertStorage:
    def migrate(self) -> None:
        return None

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def dashboard_stats(self, start: datetime, end: datetime) -> dict[str, Any]:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def claim_notifications(
        self, minimum_severity: EventSeverity, now: datetime, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def get_telegram_message_id(self, aggregate_id: str, chat_id: int) -> int | None:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def save_telegram_message_id(self, aggregate_id: str, chat_id: int, message_id: int) -> None:
        raise StorageUnavailableError("PostgreSQL is not configured")

    def ready(self) -> bool:
        return False
