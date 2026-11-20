"""Opt-in live Compose test for rsyslog through Loki/PostgreSQL."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas.event import EventSeverity
from app.storage.base import AlertQuery, EventQuery
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage
from app.syslog_generator import GeneratorConfig, Protocol, send_messages

pytestmark = [
    pytest.mark.processor_integration,
    pytest.mark.skipif(
        os.getenv("RUN_PROCESSOR_INTEGRATION") != "1",
        reason="set RUN_PROCESSOR_INTEGRATION=1 for the live Compose pipeline test",
    ),
]


def _compose(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _messages(now: datetime, interface_name: str) -> list[bytes]:
    return [
        (
            f"<189>{now:%b %d %H:%M:%S}.{sequence:03d}: %LINK-3-UPDOWN: "
            f"Interface {interface_name}, changed state to "
            f"{'up' if sequence % 2 == 0 else 'down'}"
        ).encode()
        for sequence in range(100)
    ]


def _raw_spool() -> str:
    result = _compose(
        "exec",
        "-T",
        "rsyslog",
        "sh",
        "-c",
        "test -f /var/log/networksec/raw.log && cat /var/log/networksec/raw.log",
    )
    return result.stdout


@pytest.mark.asyncio
async def test_live_pipeline_restart_replay_and_notification_deduplication() -> None:
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.fail("POSTGRES_DSN must target the running Compose PostgreSQL service")
    now = datetime.now(UTC).replace(microsecond=0)
    interface_name = f"Gi0/{int(uuid.uuid4().hex[:6], 16)}"
    messages = _messages(now, interface_name)
    config = GeneratorConfig(
        host=os.getenv("SYSLOG_TEST_HOST", "127.0.0.1"),
        port=int(os.getenv("SYSLOG_TCP_PORT", "5514")),
        protocol=Protocol.TCP,
        rate=0,
    )
    postgres = PostgresAlertStorage(dsn, Path("migrations/postgresql"))
    loki = LokiLogStorage(os.getenv("LOKI_URL", "http://127.0.0.1:3100"))
    postgres.migrate()

    assert send_messages(messages[:50], config) == 50
    _compose("restart", "processor")
    assert send_messages(messages[50:], config) == 50

    start = now - timedelta(minutes=2)
    end = now + timedelta(minutes=2)
    alert = None
    events = ()
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        page = postgres.query_alerts(
            AlertQuery(
                start=start,
                end=end,
                page=1,
                page_size=10,
                interface_name=interface_name,
            )
        )
        event_page = await loki.query_events(
            EventQuery(
                start=start,
                end=end,
                limit=200,
                interface_name=interface_name,
            )
        )
        events = event_page.items
        alert = page.items[0] if page.items else None
        if alert is not None and alert.count == 100 and len(events) == 100:
            break
        time.sleep(0.25)

    assert alert is not None
    assert alert.count == 100
    assert len({event.event_id for event in events}) == 100
    raw_spool = _raw_spool()
    assert all(message.decode() in raw_spool for message in messages)

    assert send_messages(messages, config) == 100
    time.sleep(3)
    replayed = postgres.query_alerts(
        AlertQuery(
            start=start,
            end=end,
            page=1,
            page_size=10,
            interface_name=interface_name,
        )
    )
    assert replayed.items[0].count == 100

    first_claim = postgres.claim_notifications(EventSeverity.HIGH, now + timedelta(minutes=3))
    second_claim = postgres.claim_notifications(
        EventSeverity.HIGH, now + timedelta(minutes=3, seconds=1)
    )
    assert alert.aggregate_id in {item.aggregate_id for item in first_claim}
    assert alert.aggregate_id not in {item.aggregate_id for item in second_claim}
