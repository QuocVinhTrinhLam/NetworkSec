import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.exceptions import TelegramForbiddenError
from aiogram.methods import SendMessage

from app.bot.aiogram_runtime import AiogramGateway
from app.bot.formatter import format_alert
from app.bot.telegram import (
    BotCommandHandler,
    NotificationWorker,
    PermanentTelegramError,
    TelegramBotRunner,
    alert_keyboard,
)
from app.config import Settings


class FakeGateway:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, dict[str, Any] | None]] = []
        self.edited: list[tuple[int, int, str, dict[str, Any] | None]] = []
        self.answers: list[tuple[str, str]] = []

    async def close(self) -> None:  # pragma: no cover - protocol completeness
        return None

    async def send_message(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        self.sent.append((chat_id, text, reply_markup))
        return len(self.sent) + 100

    async def edit_message(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        self.edited.append((chat_id, message_id, text, reply_markup))

    async def get_updates(self, offset: int | None = None) -> list[dict[str, Any]]:
        return []

    async def answer_callback(self, callback_id: str, text: str) -> None:
        self.answers.append((callback_id, text))


class FakeAiogramBot:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.session = SimpleNamespace(close=self._close)

    async def _close(self) -> None:
        return None

    async def send_message(self, **kwargs: Any) -> Any:
        self.calls.append(("send", kwargs))
        return SimpleNamespace(message_id=42)

    async def edit_message_text(self, **kwargs: Any) -> bool:
        self.calls.append(("edit", kwargs))
        return True

    async def answer_callback_query(self, **kwargs: Any) -> bool:
        self.calls.append(("answer", kwargs))
        return True


class FakeDatabase:
    def __init__(self, path: Path, alerts: list[dict[str, Any]] | None = None) -> None:
        self.path = path
        self.alerts = {str(alert["id"]): dict(alert) for alert in alerts or []}
        self.processed: set[str] = set()
        self.groups: dict[str, dict[str, Any]] = {}
        self.mutes: set[str] = set()
        self.states: dict[str, str] = {}

    def pending_notifications(self, limit: int = 100) -> list[dict[str, Any]]:
        return [alert for alert_id, alert in self.alerts.items() if alert_id not in self.processed][
            :limit
        ]

    def mark_notification_processed(self, alert_id: str) -> None:
        self.processed.add(alert_id)

    def is_rule_muted(self, rule_id: str) -> bool:
        return rule_id in self.mutes

    def get_notification_group(self, fingerprint: str) -> dict[str, Any] | None:
        return self.groups.get(fingerprint)

    def save_notification_group(
        self,
        fingerprint: str,
        alert_id: str,
        window_started: str,
        last_seen: str,
        alert_count: int,
        message_ids: dict[str, int] | None = None,
    ) -> None:
        self.groups[fingerprint] = {
            "alert_id": alert_id,
            "window_started": window_started,
            "last_seen": last_seen,
            "alert_count": alert_count,
            "message_ids_json": json.dumps(message_ids or {}),
        }

    def set_notification_message_ids(self, fingerprint: str, message_ids: dict[str, int]) -> None:
        self.groups[fingerprint]["message_ids_json"] = json.dumps(message_ids)

    def delete_notification_group(self, fingerprint: str) -> None:
        self.groups.pop(fingerprint, None)

    def set_state(self, key: str, value: str) -> None:
        self.states[key] = value

    @staticmethod
    def parse_message_ids(raw: str) -> dict[str, int]:
        return {str(key): int(value) for key, value in json.loads(raw).items()}

    def get_state(self, key: str) -> str | None:
        return self.states.get(key)

    def list_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        return list(self.alerts.values())[:limit]

    def top_sources(self) -> list[dict[str, Any]]:
        return [{"source_ip": "203.0.113.1", "alert_count": 2}]

    def basic_stats(self) -> dict[str, dict[str, int]]:
        return {"severity": {"high": 2}, "device_type": {"router": 2}}

    def mute_rule(self, rule_id: str, minutes: int, actor: str) -> None:
        self.mutes.add(rule_id)

    def unmute_rule(self, rule_id: str) -> bool:
        existed = rule_id in self.mutes
        self.mutes.discard(rule_id)
        return existed

    def acknowledge(self, alert_id: str, actor: str) -> bool:
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.update(status="acknowledged", acknowledged=True, acknowledged_by=actor)
        return True

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        return self.alerts.get(alert_id)

    def resolve_alert_id(self, prefix: str) -> str | None:
        matches = [alert_id for alert_id in self.alerts if alert_id.startswith(prefix)]
        return matches[0] if len(matches) == 1 else None


def _alert(alert_id: str, rule_id: str = "100210") -> dict[str, Any]:
    return {
        "id": alert_id,
        "timestamp": "2026-11-02T07:03:11+00:00",
        "severity": "critical",
        "device_name": "core-router",
        "device_type": "router",
        "source_ip": "203.0.113.5",
        "dest_ip": "10.0.99.1",
        "dst_port": 22,
        "rule_id": rule_id,
        "rule_description": "SSH brute-force",
        "mitre_id": "T1110",
        "event_count": 1,
        "status": "new",
        "recommended_response": "Block source and rotate credentials.",
    }


def test_formatter_bounds_and_escapes_hostile_fields() -> None:
    alert = _alert("a" * 64)
    alert["rule_description"] = "<script>alert(1)</script>" * 10_000
    alert["recommended_response"] = '<b onclick="steal()">owned</b>' * 10_000

    text = format_alert(alert, count=27)

    assert len(text) <= 4096
    assert "<script>" not in text
    assert '<b onclick="' not in text
    assert "&lt;script&gt;" in text
    assert "&lt;b onclick=&quot;" in text
    assert "Count: <b>27</b> in 60s" in text


def test_callback_payloads_fit_telegram_limit() -> None:
    keyboard = alert_keyboard(_alert("a" * 64))
    callback_values = [
        button["callback_data"]
        for row in keyboard["inline_keyboard"]
        for button in row
        if "callback_data" in button
    ]
    assert callback_values
    assert all(len(value.encode()) <= 64 for value in callback_values)


@pytest.mark.asyncio
async def test_aiogram_gateway_calls_mocked_bot_api() -> None:
    bot = FakeAiogramBot()
    gateway = AiogramGateway(bot)  # type: ignore[arg-type]
    keyboard = alert_keyboard(_alert("a" * 64))

    message_id = await gateway.send_message(1234, "safe", keyboard)
    await gateway.edit_message(1234, message_id, "updated", keyboard)
    await gateway.answer_callback("callback-1", "done")

    assert message_id == 42
    assert [name for name, _ in bot.calls] == ["send", "edit", "answer"]
    assert bot.calls[0][1]["reply_markup"].inline_keyboard


@pytest.mark.asyncio
async def test_aiogram_gateway_maps_blocked_chat_to_permanent_error() -> None:
    bot = FakeAiogramBot()
    gateway = AiogramGateway(bot)  # type: ignore[arg-type]

    async def forbidden() -> None:
        raise TelegramForbiddenError(SendMessage(chat_id=1234, text="safe"), "bot blocked")

    with pytest.raises(PermanentTelegramError, match="bot blocked"):
        await gateway._retry(forbidden)


@pytest.mark.asyncio
async def test_dedup_edits_one_message_instead_of_sending_duplicates(tmp_path: Path) -> None:
    alerts = [_alert("a" * 64), _alert("b" * 64)]
    database = FakeDatabase(tmp_path / "bot.db", alerts)
    gateway = FakeGateway()
    settings = Settings(
        database_path=database.path,
        allowed_chat_ids={1234},
        minimum_severity="low",
    )

    processed = await NotificationWorker(settings, database, gateway).run_once()  # type: ignore[arg-type]

    assert processed == 2
    assert len(gateway.sent) == 1
    assert len(gateway.edited) == 1
    assert "Count: <b>2</b>" in gateway.edited[0][2]


@pytest.mark.asyncio
async def test_thirty_repeated_events_produce_one_message_with_counter(tmp_path: Path) -> None:
    alerts = [_alert(f"{index:064x}") for index in range(30)]
    database = FakeDatabase(tmp_path / "thirty-events.db", alerts)
    gateway = FakeGateway()
    settings = Settings(
        database_path=database.path,
        allowed_chat_ids={1234},
        minimum_severity="low",
    )

    processed = await NotificationWorker(settings, database, gateway).run_once()  # type: ignore[arg-type]

    assert processed == 30
    assert len(gateway.sent) == 1
    assert len(gateway.edited) == 29
    assert "Count: <b>30</b>" in gateway.edited[-1][2]


@pytest.mark.asyncio
async def test_rate_limit_uses_one_updating_summary_with_top_rules(tmp_path: Path) -> None:
    alerts = [
        {**_alert("a" * 64, "rule-a"), "source_ip": "203.0.113.1"},
        {**_alert("b" * 64, "rule-b"), "source_ip": "203.0.113.2"},
        {**_alert("c" * 64, "rule-b"), "source_ip": "203.0.113.3"},
    ]
    database = FakeDatabase(tmp_path / "rate.db", alerts)
    gateway = FakeGateway()
    settings = Settings(
        database_path=database.path,
        allowed_chat_ids={1234},
        minimum_severity="low",
        telegram_rate_limit=1,
    )

    await NotificationWorker(settings, database, gateway).run_once()  # type: ignore[arg-type]

    assert len(gateway.sent) == 2  # first alert plus one summary message
    assert len(gateway.edited) == 1
    summary = gateway.edited[0][2]
    assert "2 more alerts suppressed" in summary
    assert "rule-b" in summary


@pytest.mark.asyncio
async def test_rate_limited_group_cannot_bypass_limit_with_duplicate(tmp_path: Path) -> None:
    alerts = [
        {**_alert("a" * 64, "first"), "source_ip": "203.0.113.1"},
        {**_alert("b" * 64, "blocked"), "source_ip": "203.0.113.2"},
        {**_alert("c" * 64, "blocked"), "source_ip": "203.0.113.2"},
    ]
    database = FakeDatabase(tmp_path / "rate-duplicate.db", alerts)
    gateway = FakeGateway()
    settings = Settings(
        database_path=database.path,
        allowed_chat_ids={1234},
        minimum_severity="low",
        telegram_rate_limit=1,
    )

    await NotificationWorker(settings, database, gateway).run_once()  # type: ignore[arg-type]

    assert len(gateway.sent) == 2  # one alert and one updating summary only
    assert len(gateway.edited) == 1
    assert "2 more alerts suppressed" in gateway.edited[0][2]


@pytest.mark.asyncio
async def test_permanent_destination_error_does_not_block_queue(tmp_path: Path) -> None:
    class UnreachableGateway(FakeGateway):
        async def send_message(
            self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
        ) -> int:
            raise PermanentTelegramError("chat not found")

    alert = _alert("a" * 64)
    database = FakeDatabase(tmp_path / "unreachable.db", [alert])
    gateway = UnreachableGateway()
    settings = Settings(database_path=database.path, allowed_chat_ids={9999})

    processed = await NotificationWorker(settings, database, gateway).run_once()  # type: ignore[arg-type]

    assert processed == 1
    assert alert["id"] in database.processed


@pytest.mark.asyncio
async def test_unauthorized_update_is_silent_and_does_not_log_content(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    database = FakeDatabase(tmp_path / "auth.db")
    gateway = FakeGateway()
    settings = Settings(database_path=database.path, allowed_chat_ids={1234})
    handler = BotCommandHandler(settings, database, gateway)  # type: ignore[arg-type]

    with caplog.at_level(logging.WARNING):
        handled = await handler.handle_message(
            {"chat": {"id": 9999}, "text": "/start super-secret-attacker-content"}
        )

    assert handled is False
    assert gateway.sent == []
    assert "super-secret-attacker-content" not in caplog.text
    assert "unauthorized Telegram update" in caplog.text


@pytest.mark.asyncio
async def test_commands_unmute_and_ack_callback_updates_message(tmp_path: Path) -> None:
    alert = _alert("a" * 64)
    database = FakeDatabase(tmp_path / "commands.db", [alert])
    gateway = FakeGateway()
    settings = Settings(database_path=database.path, allowed_chat_ids={1234})
    handler = BotCommandHandler(settings, database, gateway)  # type: ignore[arg-type]
    database.mute_rule("100210", 60, "test")
    fingerprint = NotificationWorker(settings, database, gateway).dedup.fingerprint(alert)  # type: ignore[arg-type]
    database.save_notification_group(
        fingerprint,
        alert["id"],
        alert["timestamp"],
        alert["timestamp"],
        30,
        {"1234": 55},
    )

    response = await handler.command("/unmute", ["100210"], 1234)
    handled = await handler.handle_callback(
        {
            "id": "callback-1",
            "data": f"a:{alert['id'][:32]}",
            "message": {"chat": {"id": 1234}, "message_id": 55},
        }
    )

    assert "unmuted" in response
    assert handled is True
    assert database.alerts[alert["id"]]["status"] == "acknowledged"
    assert gateway.answers == [("callback-1", "Alert acknowledged")]
    assert "Acknowledged by telegram:1234" in gateway.edited[0][2]
    assert "Count: <b>30</b>" in gateway.edited[0][2]


@pytest.mark.asyncio
async def test_all_command_paths_and_mute_callback(tmp_path: Path) -> None:
    alert = _alert("a" * 64)
    database = FakeDatabase(tmp_path / "commands-all.db", [alert])
    database.path.write_bytes(b"sqlite")
    database.states["event_source_health"] = "connected"
    database.states["last_alert_time"] = alert["timestamp"]
    gateway = FakeGateway()
    settings = Settings(database_path=database.path, allowed_chat_ids={1234})
    handler = BotCommandHandler(settings, database, gateway)  # type: ignore[arg-type]

    assert await handler.handle_message({"chat": {"id": 1234}, "text": "hello"})
    assert await handler.handle_message({"chat": {"id": 1234}, "text": "/help"})
    responses = [
        await handler.command("/status", [], 1234),
        await handler.command("/last", ["invalid"], 1234),
        await handler.command("/top_sources", [], 1234),
        await handler.command("/stats", [], 1234),
        await handler.command("/mute", ["100210", "bad"], 1234),
        await handler.command("/mute", ["100210", "30"], 1234),
        await handler.command("/unmute", ["not-muted"], 1234),
        await handler.command("/ack", ["missing"], 1234),
        await handler.command("/unknown", [], 1234),
    ]
    handled = await handler.handle_callback(
        {
            "id": "callback-mute",
            "data": f"m:{alert['id'][:32]}",
            "message": {"chat": {"id": 1234}, "message_id": 7},
        }
    )

    assert all(responses)
    assert handled is True
    assert "100210" in database.mutes
    assert gateway.answers[-1] == ("callback-mute", "Rule muted for 60 minutes")


@pytest.mark.asyncio
async def test_compatibility_runner_processes_message_and_callback(tmp_path: Path) -> None:
    database = FakeDatabase(tmp_path / "runner.db", [_alert("a" * 64)])
    gateway = FakeGateway()
    updates = [
        {"update_id": 10, "message": {"chat": {"id": 1234}, "text": "/help"}},
        {
            "update_id": 11,
            "callback_query": {
                "id": "callback-runner",
                "data": "x:missing",
                "message": {"chat": {"id": 1234}, "message_id": 8},
            },
        },
    ]

    async def get_updates(offset: int | None = None) -> list[dict[str, Any]]:
        assert offset is None
        return updates

    gateway.get_updates = get_updates  # type: ignore[method-assign]
    settings = Settings(database_path=database.path, allowed_chat_ids={1234})
    handler = BotCommandHandler(settings, database, gateway)  # type: ignore[arg-type]

    processed = await TelegramBotRunner(database, handler).run_once()  # type: ignore[arg-type]

    assert processed == 2
    assert database.states["telegram_update_offset"] == "12"
    assert database.states["telegram_bot_health"] == "connected"
