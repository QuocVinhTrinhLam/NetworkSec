"""Telegram transport, notification worker and compatibility command facade."""

from __future__ import annotations

import asyncio
import html
import logging
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from app.bot.auth import is_authorized
from app.bot.formatter import format_alert
from app.config import Settings
from app.db import Database
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.dedup import Deduplicator, SlidingWindowRateLimiter

LOGGER = logging.getLogger(__name__)
CALLBACK_TOKEN_LENGTH = 32


class PermanentTelegramError(RuntimeError):
    """A destination or payload error that retrying cannot repair."""


class TelegramGateway(Protocol):
    async def close(self) -> None: ...

    async def send_message(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int: ...

    async def edit_message(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None: ...

    async def get_updates(self, offset: int | None = None) -> list[dict[str, Any]]: ...

    async def answer_callback(self, callback_id: str, text: str) -> None: ...


class TelegramClient:
    """Compatibility HTTP transport; the bot process uses aiogram handlers."""

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
                    await asyncio.sleep(min(max(float(retry_after), 0.0), 30.0))
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
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
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


def alert_keyboard(
    alert: dict[str, Any], app_url: str, *, acknowledged: bool = False
) -> dict[str, Any]:
    """Build a keyboard whose callback data remains below Telegram's 64-byte cap."""
    alert_id = str(alert["id"])
    token = alert_id[:CALLBACK_TOKEN_LENGTH]
    action_row: list[dict[str, str]] = []
    if not acknowledged:
        action_row.append({"text": "✅ Acknowledge", "callback_data": f"a:{token}"})
    action_row.append({"text": "🔕 Mute rule 1h", "callback_data": f"m:{token}"})
    rows: list[list[dict[str, str]]] = [action_row]
    rows.append(
        [
            {
                "text": "🖥 Open dashboard",
                "url": f"{app_url.rstrip('/')}/alerts/{quote(alert_id, safe='')}",
            }
        ]
    )
    return {"inline_keyboard": rows}


def _summary_text(count: int, rules: Counter[str]) -> str:
    top = rules.most_common(3)
    top_text = ", ".join(f"<code>{html.escape(rule)}</code> ({hits})" for rule, hits in top)
    return (
        f"⚠️ <b>{count} more alerts suppressed</b> by the global rate limit."
        + (f"\nTop rules: {top_text}" if top_text else "")
    )


class NotificationWorker:
    """Drain the SQLite outbox, deduplicate alerts and notify allowed chats."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        telegram: TelegramGateway,
    ) -> None:
        self.settings = settings
        self.database = database
        self.telegram = telegram
        self.dedup = Deduplicator(database, settings.dedup_window_seconds)
        self.rate_limiter = SlidingWindowRateLimiter(
            settings.telegram_rate_limit, settings.telegram_rate_window_seconds
        )
        self.catalog = RulesCatalog.from_file(settings.rules_catalog)
        self._suppressed_count = 0
        self._suppressed_rules: Counter[str] = Counter()
        self._summary_message_ids: dict[int, int] = {}

    async def _publish_summary(self) -> None:
        text = _summary_text(self._suppressed_count, self._suppressed_rules)
        for chat_id in self.settings.allowed_chat_ids:
            try:
                message_id = self._summary_message_ids.get(chat_id)
                if message_id is None:
                    self._summary_message_ids[chat_id] = await self.telegram.send_message(
                        chat_id, text
                    )
                else:
                    await self.telegram.edit_message(chat_id, message_id, text)
            except PermanentTelegramError:
                LOGGER.warning(
                    "Skipped unreachable Telegram destination", extra={"chat_id": chat_id}
                )

    async def run_once(self) -> int:
        processed = 0
        for alert in self.database.pending_notifications():
            alert_id = str(alert["id"])
            rule_id = str(alert["rule_id"])
            if self.database.is_rule_muted(rule_id) or not SeverityMapper.allows(
                str(alert["severity"]), self.settings.minimum_severity
            ):
                self.database.mark_notification_processed(alert_id)
                processed += 1
                continue

            decision = self.dedup.register(alert)
            # Deduplicated alerts update the existing Telegram message; only new
            # messages consume the global message rate.
            if decision.action == "new":
                rate = self.rate_limiter.consume(time.monotonic())
                if not rate.allowed:
                    # register() persists first so retries are idempotent. A group
                    # with no Telegram message must not let the next duplicate
                    # bypass the rate limiter through the update path.
                    self.database.delete_notification_group(decision.fingerprint)
                    self._suppressed_count += 1
                    self._suppressed_rules[rule_id] += 1
                    await self._publish_summary()
                    self.database.mark_notification_processed(alert_id)
                    processed += 1
                    continue

            catalog_entry = self.catalog.get(str(alert.get("use_case_id") or ""))
            enriched = dict(alert)
            if catalog_entry:
                enriched["recommended_response"] = catalog_entry.recommended_response_for("vi")
            text = format_alert(
                enriched,
                decision.count,
                window_seconds=self.settings.dedup_window_seconds,
                timezone_name=self.settings.telegram_timezone,
            )
            keyboard = alert_keyboard(alert, self.settings.app_url)
            message_ids = dict(decision.message_ids)
            for chat_id in self.settings.allowed_chat_ids:
                key = str(chat_id)
                try:
                    if decision.action == "update" and key in message_ids:
                        await self.telegram.edit_message(chat_id, message_ids[key], text, keyboard)
                    else:
                        message_ids[key] = await self.telegram.send_message(
                            chat_id, text, keyboard
                        )
                    # Persist after each destination so a later transient failure
                    # resumes by editing instead of duplicating successful sends.
                    self.database.set_notification_message_ids(
                        decision.fingerprint, message_ids
                    )
                except PermanentTelegramError:
                    LOGGER.warning(
                        "Skipped unreachable Telegram destination", extra={"chat_id": chat_id}
                    )
            self.database.mark_notification_processed(alert_id)
            processed += 1
        return processed


class BotCommandHandler:
    """Pure command logic kept compatible with the original polling facade."""

    def __init__(self, settings: Settings, database: Database, telegram: TelegramGateway) -> None:
        self.settings = settings
        self.database = database
        self.telegram = telegram
        self.started_at = datetime.now(UTC)
        self.catalog = RulesCatalog.from_file(settings.rules_catalog)

    def _authorized(self, chat_id: Any) -> bool:
        allowed = is_authorized(chat_id, self.settings.allowed_chat_ids)
        if not allowed:
            safe_id = chat_id if isinstance(chat_id, int) else "malformed"
            LOGGER.warning("Ignored unauthorized Telegram update", extra={"chat_id": safe_id})
        return allowed

    async def handle_message(self, message: dict[str, Any]) -> bool:
        chat_id = message.get("chat", {}).get("id")
        if not self._authorized(chat_id):
            return False
        text = str(message.get("text", "")).strip()
        if not text.startswith("/"):
            return True
        command, *arguments = text.split()
        response = await self.command(command.split("@", 1)[0].lower(), arguments, int(chat_id))
        if response:
            await self.telegram.send_message(int(chat_id), response)
        return True

    async def command(self, command: str, arguments: list[str], chat_id: int) -> str:
        if command in {"/start", "/help"}:
            return (
                "<b>Network Security Monitor</b>\n"
                "/status · /last [n] · /top_sources · /stats\n"
                "/mute &lt;rule_id&gt; &lt;minutes&gt; · /unmute &lt;rule_id&gt; · "
                "/ack &lt;alert_id&gt;"
            )
        if command == "/status":
            source = html.escape(self.settings.alert_source)
            health = html.escape(
                self.database.get_state(f"{self.settings.alert_source}_health")
                or self.database.get_state("wazuh_health")
                or "unknown"
            )
            last_alert = html.escape(self.database.get_state("last_alert_time") or "none")
            queue = len(self.database.pending_notifications(limit=100))
            size_kib = (
                self.database.path.stat().st_size / 1024 if self.database.path.exists() else 0
            )
            uptime = int((datetime.now(UTC) - self.started_at).total_seconds())
            return (
                f"Source: <b>{source}</b> ({health})\nLast alert: {last_alert}\n"
                f"DB: {size_kib:.1f} KiB · Queue: {queue} · Uptime: {uptime}s"
            )
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
            )[:4096]
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
            severity = ", ".join(f"{key}={value}" for key, value in stats["severity"].items())
            devices = ", ".join(
                f"{key}={value}" for key, value in stats["device_type"].items()
            )
            return f"Severity: {severity or 'none'}\nDevice type: {devices or 'none'}"
        if command == "/mute" and len(arguments) == 2:
            try:
                minutes = max(1, min(int(arguments[1]), 10080))
            except ValueError:
                return "Usage: /mute &lt;rule_id&gt; &lt;minutes&gt;"
            rule_id = arguments[0][:64]
            self.database.mute_rule(rule_id, minutes, f"telegram:{chat_id}")
            return f"Rule <code>{html.escape(rule_id)}</code> muted for {minutes} minutes."
        if command == "/unmute" and len(arguments) == 1:
            rule_id = arguments[0][:64]
            unmute = getattr(self.database, "unmute_rule", None)
            if unmute is None:
                return "Unmute is unavailable until the database migration is applied."
            removed = bool(unmute(rule_id))
            safe_rule = html.escape(rule_id)
            return (
                f"Rule <code>{safe_rule}</code> unmuted."
                if removed
                else f"Rule <code>{safe_rule}</code> was not muted."
            )
        if command == "/ack" and arguments:
            acknowledged = self.database.acknowledge(arguments[0][:64], f"telegram:{chat_id}")
            return "Alert acknowledged." if acknowledged else "Alert not found."
        return "Unknown command. Use /help."

    def _resolve_alert_token(self, token: str) -> str | None:
        if len(token) == 64 and self.database.get_alert(token):
            return token
        resolver = getattr(self.database, "resolve_alert_id", None)
        resolved = resolver(token) if resolver else None
        return str(resolved) if resolved else None

    async def handle_callback(self, callback: dict[str, Any]) -> bool:
        message = callback.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        if not self._authorized(chat_id):
            return False
        data = str(callback.get("data", ""))
        action, _, token = data.partition(":")
        alert_id = self._resolve_alert_token(token[:CALLBACK_TOKEN_LENGTH])
        response = "Alert not found"
        if alert_id and action == "a":
            actor = f"telegram:{chat_id}"
            if self.database.acknowledge(alert_id, actor):
                response = "Alert acknowledged"
                updated = self.database.get_alert(alert_id)
                message_id = message.get("message_id")
                if updated and isinstance(message_id, int):
                    group = self.database.get_notification_group(
                        Deduplicator.fingerprint(updated)
                    )
                    count = int(group["alert_count"]) if group else int(
                        updated.get("event_count", 1)
                    )
                    catalog_entry = self.catalog.get(str(updated.get("use_case_id") or ""))
                    if catalog_entry:
                        updated = {
                            **updated,
                            "recommended_response": catalog_entry.recommended_response_for("vi"),
                        }
                    await self.telegram.edit_message(
                        int(chat_id),
                        message_id,
                        format_alert(
                            updated,
                            count,
                            window_seconds=self.settings.dedup_window_seconds,
                            timezone_name=self.settings.telegram_timezone,
                        ),
                        alert_keyboard(updated, self.settings.app_url, acknowledged=True),
                    )
        elif alert_id and action == "m":
            alert = self.database.get_alert(alert_id)
            if alert:
                self.database.mute_rule(str(alert["rule_id"]), 60, f"telegram:{chat_id}")
                response = "Rule muted for 60 minutes"
        await self.telegram.answer_callback(str(callback.get("id", "")), response)
        return True


class TelegramBotRunner:
    """Compatibility long-poll runner retained until the aiogram entrypoint is wired."""

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


class SourceHealthNotifier:
    """Notify once for an outage and once when the source recovers."""

    def __init__(self, settings: Settings, telegram: TelegramGateway) -> None:
        self.settings = settings
        self.telegram = telegram
        self._unavailable = False

    async def report_unavailable(self) -> None:
        if self._unavailable:
            return
        self._unavailable = True
        for chat_id in self.settings.allowed_chat_ids:
            await self.telegram.send_message(
                chat_id,
                "⚠️ <b>Alert source unavailable.</b> Retrying automatically.",
            )

    async def report_recovered(self) -> None:
        if not self._unavailable:
            return
        self._unavailable = False
        for chat_id in self.settings.allowed_chat_ids:
            await self.telegram.send_message(chat_id, "✅ <b>Alert source recovered.</b>")
