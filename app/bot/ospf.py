"""Deliver OSPF lifecycle transitions through one Telegram card per incident and chat."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.bot.formatter import format_ospf_notification
from app.bot.notification_models import DeliveryResult, OspfNotification, TelegramSendDeferred
from app.bot.telegram import PermanentTelegramError
from app.config import Settings
from app.schemas.event import EventSeverity
from app.services.grafana import incident_link

LOGGER = logging.getLogger(__name__)


class OspfDeliveryStorage(Protocol):
    def claim_ospf_notification(
        self, chat_ids: tuple[int, ...], minimum_severity: EventSeverity, now: datetime
    ) -> OspfNotification | None: ...

    def finish_ospf_notification(
        self,
        claim: OspfNotification,
        result: DeliveryResult,
        available_at: datetime,
        message_id: int | None = None,
    ) -> None: ...


class OspfTelegramGateway(Protocol):
    async def send_message_once(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int: ...

    async def edit_message(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None: ...


class OspfNotificationWorker:
    def __init__(
        self, settings: Settings, storage: OspfDeliveryStorage, gateway: OspfTelegramGateway
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.gateway = gateway
        self.minimum_severity = EventSeverity(settings.minimum_severity)

    async def run_once(self, now: datetime | None = None) -> int:
        chats = tuple(sorted(self.settings.allowed_chat_ids))
        if not chats:
            return 0
        for count in range(100):
            claim = await asyncio.to_thread(
                self.storage.claim_ospf_notification,
                chats,
                self.minimum_severity,
                now or datetime.now(UTC),
            )
            if claim is None:
                return count
            await self._deliver(claim, now)
        return 100

    async def _deliver(self, claim: OspfNotification, now: datetime | None) -> None:
        text = format_ospf_notification(claim, self.settings.telegram_timezone)
        url = incident_link(self.settings, claim.aggregate_id)
        keyboard = {"inline_keyboard": [[{"text": "Open in Grafana", "url": url}]]} if url else None
        result: DeliveryResult = "delivered"
        delay = 0.0
        message_id = claim.message_id
        try:
            if message_id is None:
                message_id = await self.gateway.send_message_once(claim.chat_id, text, keyboard)
            else:
                await self.gateway.edit_message(claim.chat_id, message_id, text, keyboard)
        except TelegramSendDeferred as exc:
            result, delay = "pending", max(1.0, exc.retry_after)
        except PermanentTelegramError:
            result = "skipped"
        except Exception:
            if message_id is None:
                result = "uncertain"
            else:
                result, delay = "pending", 30.0
        if result != "delivered":
            LOGGER.warning(
                "OSPF Telegram delivery recorded as %s",
                result,
                extra={"notification_id": claim.notification_id},
            )
        available_at = (now or datetime.now(UTC)) + timedelta(seconds=delay)
        await asyncio.to_thread(
            self.storage.finish_ospf_notification, claim, result, available_at, message_id
        )
