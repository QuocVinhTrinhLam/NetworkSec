"""Dedicated aiogram worker process used by Docker Compose."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.bot.aggregated import AggregatedNotificationWorker
from app.bot.aiogram_runtime import AiogramBotRuntime
from app.bot.ospf import OspfNotificationWorker
from app.bot.telegram import NotificationWorker
from app.config import get_settings
from app.db import Database
from app.logging_config import configure_logging
from app.services.silent_devices import SilentDeviceWatcher
from app.storage.postgres import PostgresAlertStorage

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
    runtime = AiogramBotRuntime(settings, database)
    ospf_notifications = None
    if settings.postgres_dsn:
        alert_storage = PostgresAlertStorage(
            settings.postgres_dsn,
            settings.postgres_migrations_path,
            connect_timeout=settings.postgres_connect_timeout_seconds,
        )
        alert_storage.migrate()
        notifications: NotificationWorker | AggregatedNotificationWorker = (
            AggregatedNotificationWorker(settings, alert_storage, runtime.gateway)
        )
        ospf_notifications = OspfNotificationWorker(settings, alert_storage, runtime.gateway)
    else:
        notifications = NotificationWorker(settings, database, runtime.gateway)
    silent_watcher = SilentDeviceWatcher(settings, database)
    await runtime.bot.get_me()
    READY_FILE.touch(mode=0o600)
    database.set_state("event_source_health", "connected")

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
    if ospf_notifications is not None:
        tasks.append(
            asyncio.create_task(
                _repeat(
                    ospf_notifications.run_once,
                    settings.notification_interval_seconds,
                    "ospf_notifications",
                )
            )
        )
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
