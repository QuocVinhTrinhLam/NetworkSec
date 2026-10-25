"""Low-memory Telegram Bot API client, commands and notification worker."""

from __future__ import annotations

import asyncio
import html
import logging
import time
from typing import Any

import httpx

from app.bot.auth import is_authorized
from app.bot.formatter import format_alert
from app.config import Settings
from app.db import Database
from app.services.catalog import SeverityMapper
from app.services.dedup import Deduplicator, SlidingWindowRateLimiter

LOGGER = logging.getLogger(__name__)


class TelegramClient:
    """Small async Telegram API wrapper with bounded exponential backoff."""

    def __init__(self, token: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.client = httpx.AsyncClient(
            base_url=f"https://api.telegram.org/bot{token}",
            timeout=httpx.Timeout(35.0),
            transport=transport,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(4):
            try:
                response = await self.client.post(f"/{method}", json=payload)
                if response.status_code == 429:
                    retry_after = response.json().get("parameters", {}).get("retry_after", 1)
                    await asyncio.sleep(min(float(retry_after), 10.0))
                    continue
                response.raise_for_status()
                data = response.json()
                if not data.get("ok"):
                    raise RuntimeError("Telegram API returned ok=false")
                return data
            except (httpx.HTTPError, RuntimeError):
                if attempt == 3:
                    raise RuntimeError("Telegram request failed after retries") from None
                await asyncio.sleep(2**attempt)
        raise RuntimeError("Telegram request retries exhausted")

    async def send_message(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        data = await self.call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                "reply_markup": reply_markup,
            },
        )
        return int(data["result"]["message_id"])

    async def edit_message(
        self, chat_id: int, message_id: int, text: str, reply_markup: dict[str, Any]
    ) -> None:
        await self.call(
            "editMessageText",
            {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                "reply_markup": reply_markup,
            },
        )

    async def get_updates(self, offset: int | None = None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {
            "timeout": 25,
            "allowed_updates": ["message", "callback_query"],
        }
        if offset is not None:
            payload["offset"] = offset
        data = await self.call("getUpdates", payload)
        return list(data.get("result", []))

    async def answer_callback(self, callback_id: str, text: str) -> None:
        await self.call(
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": text[:200]},
        )


def alert_keyboard(alert: dict[str, Any], app_url: str) -> dict[str, Any]:
    alert_id = str(alert["id"])
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Acknowledge", "callback_data": f"ack:{alert_id}"},
                {"text": "🔕 Mute 1h", "callback_data": f"mute:{alert['rule_id']}:60"},
            ],
            [{"text": "🖥 Open dashboard", "url": f"{app_url.rstrip('/')}/alerts/{alert_id}"}],
        ]
    }


class NotificationWorker:
    """Drain the SQLite outbox, deduplicate alerts and notify allowed chats."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        telegram: TelegramClient,
    ) -> None:
        self.settings = settings
        self.database = database
        self.telegram = telegram
        self.dedup = Deduplicator(database, settings.dedup_window_seconds)
        self.rate_limiter = SlidingWindowRateLimiter(
            settings.telegram_rate_limit, settings.telegram_rate_window_seconds
        )

    async def run_once(self) -> int:
        processed = 0
        for alert in self.database.pending_notifications():
            if self.database.is_rule_muted(str(alert["rule_id"])):
                self.database.mark_notification_processed(str(alert["id"]))
                processed += 1
                continue
            if not SeverityMapper.allows(str(alert["severity"]), self.settings.minimum_severity):
                self.database.mark_notification_processed(str(alert["id"]))
                processed += 1
                continue
            decision = self.dedup.register(alert)
            rate = self.rate_limiter.consume(time.monotonic())
            if not rate.allowed:
                self.database.mark_notification_processed(str(alert["id"]))
                processed += 1
                continue
            if rate.suppressed_summary:
                summary = f"⚠️ {rate.suppressed_summary} alerts suppressed by the global rate limit."
                for chat_id in self.settings.allowed_chat_ids:
                    await self.telegram.send_message(chat_id, summary)
            text = format_alert(alert, decision.count)
            keyboard = alert_keyboard(alert, self.settings.app_url)
            message_ids = dict(decision.message_ids)
            for chat_id in self.settings.allowed_chat_ids:
                key = str(chat_id)
                if decision.action == "update" and key in message_ids:
                    await self.telegram.edit_message(chat_id, message_ids[key], text, keyboard)
                else:
                    message_ids[key] = await self.telegram.send_message(chat_id, text, keyboard)
            self.database.set_notification_message_ids(decision.fingerprint, message_ids)
            self.database.mark_notification_processed(str(alert["id"]))
            processed += 1
        return processed


class BotCommandHandler:
    """Handle analyst commands while silently ignoring unauthorized chats."""

    def __init__(self, settings: Settings, database: Database, telegram: TelegramClient) -> None:
        self.settings = settings
        self.database = database
        self.telegram = telegram

    async def handle_message(self, message: dict[str, Any]) -> bool:
        chat_id = message.get("chat", {}).get("id")
        if not is_authorized(chat_id, self.settings.allowed_chat_ids):
            return False
        text = str(message.get("text", "")).strip()
        if not text.startswith("/"):
            return True
        command, *arguments = text.split()
        command = command.split("@", 1)[0].lower()
        response = await self._command(command, arguments, int(chat_id))
        if response:
            await self.telegram.send_message(int(chat_id), response)
        return True

    async def _command(self, command: str, arguments: list[str], chat_id: int) -> str:
        if command in {"/start", "/help"}:
            return (
                "<b>Network Security Monitor</b>\n"
                "/status · /last [n] · /top_sources · /stats\n"
                "/mute &lt;rule_id&gt; &lt;minutes&gt; · /ack &lt;alert_id&gt;"
            )
        if command == "/status":
            health = html.escape(self.database.get_state("wazuh_health") or "unknown")
            last_alert = html.escape(self.database.get_state("last_alert_time") or "none")
            queue = len(self.database.pending_notifications(limit=100))
            return f"Wazuh: <b>{health}</b>\nLast alert: {last_alert}\nQueue: {queue}"
        if command == "/last":
            try:
                limit = max(1, min(int(arguments[0]), 20)) if arguments else 5
            except ValueError:
                limit = 5
            alerts = self.database.list_alerts(limit)
            return (
                "\n".join(
                    f"<code>{html.escape(str(row['id']))}</code> "
                    f"[{html.escape(str(row['severity']))}] "
                    f"{html.escape(str(row['rule_description']))}"
                    for row in alerts
                )
                or "No alerts."
            )
        if command == "/top_sources":
            rows = self.database.top_sources()
            return (
                "\n".join(
                    f"<code>{html.escape(str(row['source_ip']))}</code>: {row['alert_count']}"
                    for row in rows
                )
                or "No source IP data."
            )
        if command == "/stats":
            stats = self.database.basic_stats()
            return "Severity: " + ", ".join(
                f"{key}={value}" for key, value in stats["severity"].items()
            )
        if command == "/mute" and len(arguments) == 2:
            try:
                minutes = int(arguments[1])
            except ValueError:
                return "Usage: /mute &lt;rule_id&gt; &lt;minutes&gt;"
            self.database.mute_rule(arguments[0], minutes, f"telegram:{chat_id}")
            safe_rule = html.escape(arguments[0])
            return f"Rule <code>{safe_rule}</code> muted for {minutes} minutes."
        if command == "/ack" and arguments:
            acknowledged = self.database.acknowledge(arguments[0], f"telegram:{chat_id}")
            return "Alert acknowledged." if acknowledged else "Alert not found."
        return "Unknown command. Use /help."

    async def handle_callback(self, callback: dict[str, Any]) -> bool:
        message = callback.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        if not is_authorized(chat_id, self.settings.allowed_chat_ids):
            return False
        data = str(callback.get("data", ""))
        actor = f"telegram:{chat_id}"
        response = "Unsupported action"
        if data.startswith("ack:"):
            alert_id = data.split(":", 1)[1]
            response = (
                "Alert acknowledged"
                if self.database.acknowledge(alert_id, actor)
                else "Alert not found"
            )
        elif data.startswith("mute:"):
            parts = data.split(":", 2)
            if len(parts) == 3:
                try:
                    minutes = int(parts[2])
                    self.database.mute_rule(parts[1], minutes, actor)
                    response = f"Rule muted for {minutes} minutes"
                except ValueError:
                    response = "Invalid mute duration"
        await self.telegram.answer_callback(str(callback.get("id", "")), response)
        return True


class TelegramBotRunner:
    """Long-poll Telegram updates and persist the offset across restarts."""

    def __init__(self, database: Database, handler: BotCommandHandler) -> None:
        self.database = database
        self.handler = handler

    async def run_once(self) -> int:
        raw_offset = self.database.get_state("telegram_update_offset")
        offset = int(raw_offset) if raw_offset else None
        updates = await self.handler.telegram.get_updates(offset)
        for update in updates:
            if "message" in update:
                await self.handler.handle_message(update["message"])
            elif "callback_query" in update:
                await self.handler.handle_callback(update["callback_query"])
            offset = int(update["update_id"]) + 1
            self.database.set_state("telegram_update_offset", str(offset))
        self.database.set_state("telegram_bot_health", "connected")
        return len(updates)
