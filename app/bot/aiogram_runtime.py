"""Aiogram 3 polling runtime and asynchronous update handlers."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from aiogram import Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramNotFound,
    TelegramRetryAfter,
    TelegramServerError,
    TelegramUnauthorizedError,
)
from aiogram.types import BotCommand, CallbackQuery, InlineKeyboardMarkup, Message

from app.bot.notification_models import TelegramSendDeferred
from app.bot.telegram import BotCommandHandler, PermanentTelegramError
from app.config import Settings
from app.db import Database

LOGGER = logging.getLogger(__name__)
ResultT = TypeVar("ResultT")


def _markup(value: dict[str, Any] | None) -> InlineKeyboardMarkup | None:
    return InlineKeyboardMarkup.model_validate(value) if value else None


class AiogramGateway:
    """Small retrying facade over aiogram's Bot methods."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    async def _retry(self, operation: Callable[[], Awaitable[ResultT]]) -> ResultT:
        for attempt in range(4):
            try:
                return await operation()
            except (
                TelegramBadRequest,
                TelegramForbiddenError,
                TelegramNotFound,
                TelegramUnauthorizedError,
            ) as error:
                raise PermanentTelegramError(str(error)) from None
            except TelegramRetryAfter as error:
                if attempt == 3:
                    raise
                await asyncio.sleep(min(max(float(error.retry_after), 0.0), 30.0))
            except (TelegramNetworkError, TelegramServerError):
                if attempt == 3:
                    raise
                await asyncio.sleep(2**attempt)
        raise RuntimeError("Telegram request retries exhausted")

    async def close(self) -> None:
        await self.bot.session.close()

    async def send_message(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        message = await self._retry(
            lambda: self.bot.send_message(
                chat_id=chat_id,
                text=text,
                reply_markup=_markup(reply_markup),
            )
        )
        return message.message_id

    async def edit_message(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        async def edit() -> object:
            try:
                return await self.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_id,
                    text=text,
                    reply_markup=_markup(reply_markup),
                )
            except TelegramBadRequest as error:
                if "message is not modified" in str(error).lower():
                    return True
                raise

        await self._retry(edit)

    async def send_message_once(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        """Keep an ambiguous first send from being replayed by the transport."""
        try:
            message = await self.bot.send_message(
                chat_id=chat_id,
                text=text,
                reply_markup=_markup(reply_markup),
            )
        except TelegramRetryAfter as error:
            raise TelegramSendDeferred(error.retry_after) from None
        except (
            TelegramBadRequest,
            TelegramForbiddenError,
            TelegramNotFound,
            TelegramUnauthorizedError,
        ):
            raise PermanentTelegramError("Telegram rejected the send request") from None
        return message.message_id

    async def get_updates(self, offset: int | None = None) -> list[dict[str, Any]]:
        updates = await self._retry(
            lambda: self.bot.get_updates(
                offset=offset,
                timeout=25,
                allowed_updates=["message", "callback_query"],
            )
        )
        return [update.model_dump(mode="json", exclude_none=True) for update in updates]

    async def answer_callback(self, callback_id: str, text: str) -> None:
        await self._retry(
            lambda: self.bot.answer_callback_query(
                callback_query_id=callback_id,
                text=text[:200],
            )
        )


class AiogramBotRuntime:
    """Own the aiogram dispatcher while reusing the tested command service."""

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.bot = Bot(
            token=settings.telegram_bot_token,
            default=DefaultBotProperties(
                parse_mode=ParseMode.HTML,
                link_preview_is_disabled=True,
            ),
        )
        self.gateway = AiogramGateway(self.bot)
        self.commands = BotCommandHandler(settings, database, self.gateway)
        self.router = Router(name="networksec-telegram")
        self.router.message.register(self._message)
        self.router.callback_query.register(self._callback)
        self.dispatcher = Dispatcher()
        self.dispatcher.include_router(self.router)

    async def _message(self, message: Message) -> None:
        await self.commands.handle_message(
            {
                "chat": {"id": message.chat.id},
                "text": message.text or "",
            }
        )

    async def _callback(self, callback: CallbackQuery) -> None:
        message = callback.message
        chat_id = message.chat.id if message else callback.from_user.id
        message_id = message.message_id if message else None
        await self.commands.handle_callback(
            {
                "id": callback.id,
                "data": callback.data or "",
                "message": {"chat": {"id": chat_id}, "message_id": message_id},
            }
        )

    async def run(self) -> None:
        """Poll forever; aiogram contains update-level failures internally."""
        await self.bot.set_my_commands(
            [
                BotCommand(command="start", description="Show bot help"),
                BotCommand(command="status", description="Show source and queue health"),
                BotCommand(command="last", description="Show recent alerts"),
                BotCommand(command="top_sources", description="Show top source IPs"),
                BotCommand(command="stats", description="Show 24-hour statistics"),
                BotCommand(command="mute", description="Mute a rule"),
                BotCommand(command="unmute", description="Unmute a rule"),
                BotCommand(command="ack", description="Acknowledge an alert"),
            ]
        )
        await self.dispatcher.start_polling(
            self.bot,
            allowed_updates=self.dispatcher.resolve_used_update_types(),
            handle_signals=True,
        )

    async def close(self) -> None:
        await self.dispatcher.stop_polling()
        await self.gateway.close()
