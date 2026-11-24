from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.bot.aggregated import AggregatedNotificationWorker
from app.config import Settings
from app.schemas.api import AlertRecord
from app.schemas.event import EventSeverity, EventType

NOW = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
ALERT_ID = "d" * 64


def _record(count: int) -> AlertRecord:
    return AlertRecord(
        aggregate_id=ALERT_ID,
        rule_id="interface-link-state",
        event_family="link_state",
        device_name="core-sw-01",
        interface_name="Gi0/1",
        event_types=(EventType.LINK_DOWN, EventType.LINK_UP),
        window_start=NOW,
        window_end=NOW + timedelta(minutes=1),
        count=count,
        first_seen=NOW,
        last_seen=NOW + timedelta(seconds=50),
        severity=EventSeverity.HIGH,
        status="new",
        status_changed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


class NotificationStore:
    def __init__(self) -> None:
        self.batches: list[tuple[AlertRecord, ...]] = [(_record(100),), (), (_record(101),)]
        self.messages: dict[tuple[str, int], int] = {}
        self.thresholds: list[EventSeverity] = []

    def claim_notifications(
        self, minimum_severity: EventSeverity, now: datetime, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        self.thresholds.append(minimum_severity)
        return self.batches.pop(0)

    def get_telegram_message_id(self, aggregate_id: str, chat_id: int) -> int | None:
        return self.messages.get((aggregate_id, chat_id))

    def save_telegram_message_id(self, aggregate_id: str, chat_id: int, message_id: int) -> None:
        self.messages[(aggregate_id, chat_id)] = message_id


class NotificationGateway:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, dict[str, Any] | None]] = []
        self.edited: list[tuple[int, int, str, dict[str, Any] | None]] = []

    async def close(self) -> None:
        return None

    async def send_message(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        self.sent.append((chat_id, text, reply_markup))
        return 700

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
        return None


@pytest.mark.asyncio
async def test_aggregate_notifications_use_threshold_claim_and_edit_without_duplicates(
    tmp_path: Path,
) -> None:
    store = NotificationStore()
    gateway = NotificationGateway()
    settings = Settings(
        database_path=tmp_path / "notifications.db",
        allowed_chat_ids={1234},
        minimum_severity="high",
        grafana_public_url="https://metrics.example.test/observability",
    )
    worker = AggregatedNotificationWorker(settings, store, gateway)  # type: ignore[arg-type]

    assert await worker.run_once(NOW) == 1
    assert await worker.run_once(NOW + timedelta(seconds=10)) == 0
    assert await worker.run_once(NOW + timedelta(minutes=6)) == 1

    assert store.thresholds == [EventSeverity.HIGH] * 3
    assert len(gateway.sent) == 1
    assert gateway.sent[0][0] == 1234
    assert "Count: <b>100</b>" in gateway.sent[0][1]
    assert len(gateway.edited) == 1
    assert gateway.edited[0][1] == 700
    assert "Count: <b>101</b>" in gateway.edited[0][2]
    assert (
        gateway.sent[0][2]
        == gateway.edited[0][3]
        == {
            "inline_keyboard": [
                [
                    {
                        "text": "Open in Grafana",
                        "url": (
                            "https://metrics.example.test/observability/d/network-incident-operations"
                            f"?var-incident={ALERT_ID}"
                        ),
                    }
                ]
            ]
        }
    )
