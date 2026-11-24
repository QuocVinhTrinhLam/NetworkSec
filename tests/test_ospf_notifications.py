from unittest.mock import AsyncMock

import pytest
from aiogram.exceptions import TelegramNetworkError, TelegramRetryAfter, TelegramUnauthorizedError
from aiogram.methods import SendMessage

from app.bot.aiogram_runtime import AiogramGateway
from app.bot.notification_models import TelegramSendDeferred
from app.bot.telegram import PermanentTelegramError
from app.config import Settings
from app.services.grafana import incident_link


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
        "https://[bad",
        "https://example.com:broken",
        "https://api:8000",
        "https://127.0.0.1",
    ],
)
def test_invalid_or_local_grafana_urls_have_no_link(base: str) -> None:
    assert incident_link(Settings(grafana_public_url=base), "a" * 64) is None


def test_grafana_link_preserves_subpath_and_quotes_incident_id() -> None:
    settings = Settings(grafana_public_url="https://metrics.example.com/lab/")
    assert incident_link(settings, "id/segment & next") == (
        "https://metrics.example.com/lab/d/network-incident-operations"
        "?var-incident=id%2Fsegment+%26+next"
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
