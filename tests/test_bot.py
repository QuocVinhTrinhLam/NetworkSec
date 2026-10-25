from pathlib import Path

import httpx
import pytest

from app.bot.auth import is_authorized
from app.bot.formatter import format_alert
from app.bot.telegram import BotCommandHandler, TelegramClient
from app.config import Settings
from app.db import Database


def test_authorization_is_fail_closed() -> None:
    allowed = {1234}
    assert is_authorized(1234, allowed)
    assert not is_authorized(9999, allowed)
    assert not is_authorized("attacker", allowed)
    assert not is_authorized(None, allowed)


def test_formatter_escapes_attacker_controlled_fields() -> None:
    text = format_alert(
        {
            "severity": "critical",
            "rule_description": "<b>owned</b>",
            "device_name": "router&switch",
            "device_type": "router",
            "source_ip": "<script>",
            "dest_ip": "10.0.0.1",
            "rule_id": "1",
            "mitre_id": None,
            "timestamp": "now",
        }
    )
    assert "&lt;b&gt;owned&lt;/b&gt;" in text
    assert "<script>" not in text


@pytest.mark.asyncio
async def test_unauthorized_command_gets_no_response(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    database = Database(tmp_path / "bot.db")
    database.initialize()
    settings = Settings(database_path=tmp_path / "bot.db", allowed_chat_ids={1234})
    client = TelegramClient("not-a-real-token", httpx.MockTransport(handler))
    command_handler = BotCommandHandler(settings, database, client)
    try:
        handled = await command_handler.handle_message({"chat": {"id": 9999}, "text": "/status"})
    finally:
        await client.close()

    assert handled is False
    assert calls == 0


@pytest.mark.asyncio
async def test_unauthorized_callback_gets_no_response(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ok": True, "result": True})

    database = Database(tmp_path / "callback.db")
    database.initialize()
    settings = Settings(database_path=tmp_path / "callback.db", allowed_chat_ids={1234})
    client = TelegramClient("not-a-real-token", httpx.MockTransport(handler))
    command_handler = BotCommandHandler(settings, database, client)
    try:
        handled = await command_handler.handle_callback(
            {
                "id": "callback-1",
                "data": "ack:anything",
                "message": {"chat": {"id": 9999}},
            }
        )
    finally:
        await client.close()

    assert handled is False
    assert calls == 0
