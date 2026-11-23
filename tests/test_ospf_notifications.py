from unittest.mock import AsyncMock

import pytest
from aiogram.exceptions import TelegramNetworkError, TelegramRetryAfter, TelegramUnauthorizedError
from aiogram.methods import SendMessage

from app.bot.aiogram_runtime import AiogramGateway
from app.bot.notification_models import TelegramSendDeferred
from app.bot.ospf import _dashboard_keyboard
from app.bot.telegram import PermanentTelegramError


@pytest.mark.parametrize(
    "base",
    [
        "",
        "not-a-url",
        "javascript:run()",
        "http://localhost:8000",
        "https://[::1]:8080",
        "https://analyst@example.com",
        "https://example.com?a=b",
        "https://not|a|host",
    ],
)
def test_invalid_or_local_dashboard_urls_have_no_button(base: str) -> None:
    assert _dashboard_keyboard(base, "a" * 64) is None


def test_dashboard_href_uses_configured_prefix_and_quoted_incident_id() -> None:
    keyboard = _dashboard_keyboard("https://dashboard.example.com/lab/", "id/segment")
    assert keyboard is not None
    assert keyboard["inline_keyboard"][0][0]["url"] == (
        "https://dashboard.example.com/lab/alerts/id%2Fsegment"
    )


@pytest.mark.asyncio
async def test_first_send_does_not_retry_ambiguous_network_error() -> None:
    bot = AsyncMock()
    method = SendMessage(chat_id=123, text="test")
    bot.send_message.side_effect = TelegramNetworkError(method=method, message="timeout")
    with pytest.raises(TelegramNetworkError):
        await AiogramGateway(bot).send_message_once(123, "test")
    assert bot.send_message.await_count == 1


@pytest.mark.asyncio
async def test_first_send_surfaces_explicit_rate_limit_for_durable_reschedule() -> None:
    bot = AsyncMock()
    method = SendMessage(chat_id=123, text="test")
    bot.send_message.side_effect = TelegramRetryAfter(method=method, message="slow", retry_after=7)
    with pytest.raises(TelegramSendDeferred) as error:
        await AiogramGateway(bot).send_message_once(123, "test")
    assert error.value.retry_after == 7 and bot.send_message.await_count == 1


@pytest.mark.asyncio
async def test_qa_invalid_token_response_is_permanent_without_network_or_retry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bot = AsyncMock()
    method = SendMessage(chat_id=123, text="QA synthetic alert")
    bot.send_message.side_effect = TelegramUnauthorizedError(
        method=method, message="Unauthorized QA_FAKE_PRIVATE_DETAIL"
    )
    gateway = AiogramGateway(bot)
    with pytest.raises(PermanentTelegramError, match="^Telegram rejected the send request$"):
        await gateway.send_message_once(123, "QA synthetic alert")
    assert bot.send_message.await_count == 1
    assert "QA_FAKE_PRIVATE_DETAIL" not in caplog.text
