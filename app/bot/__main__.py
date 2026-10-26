"""Dedicated aiogram worker process used by Docker Compose."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.adapters import build_adapter
from app.bot.aiogram_runtime import AiogramBotRuntime
from app.bot.telegram import NotificationWorker, SourceHealthNotifier
from app.config import get_settings
from app.db import Database
from app.logging_config import configure_logging
from app.services.silent_devices import SilentDeviceWatcher

LOGGER = logging.getLogger(__name__)
READY_FILE = Path("/tmp/bot.ready")


async def _repeat(operation: Callable[[], Awaitable[object]], interval: int, name: str) -> None:
    while True:
        try:
            await operation()
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Bot worker operation failed", extra={"worker": name})
        await asyncio.sleep(max(1, interval))


async def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, json_logs=settings.json_logs)
    if not settings.telegram_bot_token or not settings.allowed_chat_ids:
        raise SystemExit("TELEGRAM_BOT_TOKEN and ALLOWED_CHAT_IDS are required by the bot service")

    database = Database(settings.database_path)
    database.initialize()
    adapter = build_adapter(settings)
    runtime = AiogramBotRuntime(settings, database)
    notifications = NotificationWorker(settings, database, runtime.gateway)
    silent_watcher = SilentDeviceWatcher(settings, database)
    health = SourceHealthNotifier(settings, runtime.gateway)

    await runtime.bot.get_me()
    READY_FILE.touch(mode=0o600)
    if settings.alert_source == "wazuh":
        try:
            await adapter.fetch_new_alerts()
        except NotImplementedError as error:
            database.set_state("wazuh_health", "not-implemented")
            LOGGER.warning("Wazuh adapter unavailable in Phase 1", extra={"reason": str(error)})
            await health.report_unavailable()
    else:
        database.set_state("mock_health", "connected")

    async def watch_silent_devices() -> object:
        return silent_watcher.run_once()

    tasks = [
        asyncio.create_task(
            _repeat(
                notifications.run_once,
                settings.notification_interval_seconds,
                "notifications",
            )
        ),
        asyncio.create_task(
            _repeat(watch_silent_devices, settings.poll_interval_seconds, "silent_devices")
        ),
    ]
    try:
        await runtime.run()
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        READY_FILE.unlink(missing_ok=True)
        with contextlib.suppress(RuntimeError):
            await runtime.close()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
