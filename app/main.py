"""FastAPI application and supervised background polling loops."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.bot.telegram import (
    BotCommandHandler,
    NotificationWorker,
    TelegramBotRunner,
    TelegramClient,
)
from app.config import BASE_DIR, Settings, get_settings
from app.db import Database
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.wazuh import WazuhClient, WazuhPoller
from app.web.routes import create_router

LOGGER = logging.getLogger(__name__)


async def repeat(
    operation: Callable[[], Awaitable[object]], interval: int, name: str, database: Database
) -> None:
    """Run a background operation forever while containing transient failures."""
    while True:
        try:
            await operation()
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Background worker failed", extra={"worker": name})
            database.set_state(f"{name}_health", "error")
        await asyncio.sleep(max(1, interval))


def create_app(settings: Settings | None = None) -> FastAPI:
    current = settings or get_settings()
    database = Database(current.database_path)
    database.initialize()
    logging.basicConfig(
        level=getattr(logging, current.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # httpx logs complete URLs; Telegram URLs contain the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        tasks: list[asyncio.Task[None]] = []
        closers: list[Callable[[], Awaitable[None]]] = []
        telegram: TelegramClient | None = None
        if current.telegram_bot_token and current.allowed_chat_ids:
            telegram = TelegramClient(current.telegram_bot_token)
            notifier = NotificationWorker(current, database, telegram)
            command_handler = BotCommandHandler(current, database, telegram)
            bot_runner = TelegramBotRunner(database, command_handler)
            tasks.extend(
                [
                    asyncio.create_task(
                        repeat(
                            notifier.run_once,
                            current.notification_interval_seconds,
                            "telegram_notifications",
                            database,
                        )
                    ),
                    asyncio.create_task(repeat(bot_runner.run_once, 1, "telegram_bot", database)),
                ]
            )
            closers.append(telegram.close)
        if not current.mock_mode:
            wazuh_client = WazuhClient(current)
            wazuh_poller = WazuhPoller(
                wazuh_client,
                database,
                SeverityMapper.from_file(current.severity_config),
                RulesCatalog.from_file(current.rules_catalog),
            )
            outage_reported = False

            async def poll_wazuh() -> object:
                nonlocal outage_reported
                try:
                    result = await wazuh_poller.run_once()
                    outage_reported = False
                    return result
                except Exception:
                    database.set_state("wazuh_health", "disconnected")
                    if telegram is not None and not outage_reported:
                        for chat_id in current.allowed_chat_ids:
                            await telegram.send_message(
                                chat_id,
                                "⚠️ <b>Wazuh connection unavailable.</b> Retrying automatically.",
                            )
                        outage_reported = True
                    raise

            tasks.append(
                asyncio.create_task(
                    repeat(
                        poll_wazuh,
                        current.poll_interval_seconds,
                        "wazuh",
                        database,
                    )
                )
            )
            closers.append(wazuh_client.close)
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            for close in closers:
                await close()

    app = FastAPI(title=current.app_name, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=current.session_secret,
        https_only=current.session_https_only,
        same_site="lax",
        max_age=8 * 60 * 60,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    templates = Jinja2Templates(directory=BASE_DIR / "app" / "templates")
    app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")
    app.include_router(create_router(database, current, templates))
    app.state.database = database
    app.state.settings = current
    return app


app = create_app()
