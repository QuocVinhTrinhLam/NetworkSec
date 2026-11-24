"""Telegram delivery for PostgreSQL-backed aggregated alerts."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.bot.formatter import format_alert
from app.bot.telegram import PermanentTelegramError, TelegramGateway
from app.config import Settings
from app.schemas.api import AlertRecord
from app.schemas.event import EventSeverity
from app.services.grafana import incident_link
from app.storage.base import AlertStateStorage

LOGGER = logging.getLogger(__name__)


class AggregatedNotificationWorker:
    """Claim aggregate updates once, then send or edit one message per chat."""

    def __init__(
        self,
        settings: Settings,
        alerts: AlertStateStorage,
        telegram: TelegramGateway,
    ) -> None:
        self.settings = settings
        self.alerts = alerts
        self.telegram = telegram
        try:
            self.minimum_severity = EventSeverity(settings.minimum_severity)
        except ValueError as exc:
            raise ValueError(
                "TELEGRAM_MIN_SEVERITY must be low, medium, high, or critical"
            ) from exc

    async def run_once(self, now: datetime | None = None) -> int:
        claimed = self.alerts.claim_notifications(
            self.minimum_severity,
            (now or datetime.now(UTC)).astimezone(UTC),
        )
        for alert in claimed:
            await self._deliver(alert)
        return len(claimed)

    async def _deliver(self, alert: AlertRecord) -> None:
        text = format_alert(_telegram_view(alert), count=alert.count, window_seconds=_window(alert))
        url = incident_link(self.settings, alert.aggregate_id)
        keyboard = {"inline_keyboard": [[{"text": "Open in Grafana", "url": url}]]} if url else None
        for chat_id in sorted(self.settings.allowed_chat_ids):
            try:
                message_id = self.alerts.get_telegram_message_id(alert.aggregate_id, chat_id)
                if message_id is None:
                    message_id = await self.telegram.send_message(chat_id, text, keyboard)
                    self.alerts.save_telegram_message_id(alert.aggregate_id, chat_id, message_id)
                else:
                    await self.telegram.edit_message(chat_id, message_id, text, keyboard)
            except PermanentTelegramError:
                LOGGER.warning(
                    "Skipped unreachable Telegram destination",
                    extra={"chat_id": chat_id, "aggregate_id": alert.aggregate_id},
                )


def _window(alert: AlertRecord) -> int:
    return max(1, int((alert.window_end - alert.window_start).total_seconds()))


def _telegram_view(alert: AlertRecord) -> dict[str, Any]:
    return {
        "id": alert.aggregate_id,
        "timestamp": alert.last_seen.isoformat(),
        "severity": alert.severity.value,
        "device_name": alert.device_name,
        "interface": alert.interface_name,
        "rule_id": alert.rule_id,
        "rule_description": alert.event_family.replace("_", " ").title(),
        "event_count": alert.count,
        "status": alert.status.value,
        "acknowledged_by": alert.acknowledged_by,
    }
