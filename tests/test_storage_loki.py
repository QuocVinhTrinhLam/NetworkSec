from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import EventQuery, InvalidCursorError
from app.storage.loki import LokiLogStorage

BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _event(sequence: int, timestamp: datetime = BASE_TIME) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        received_at=timestamp + timedelta(milliseconds=10),
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="core-sw-01",
        interface_name="GigabitEthernet0/1",
        interface_state="down",
        message="Interface changed state to down",
        raw_message=f"sequence={sequence} interface down",
        parser_name="loki-test",
    )


@pytest.mark.asyncio
async def test_loki_push_uses_low_cardinality_labels() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        storage = LokiLogStorage("http://loki:3100", client=client)
        await storage.push_event(_event(1))

    stream = captured["streams"][0]["stream"]  # type: ignore[index]
    assert stream == {
        "job": "network-events",
        "schema_version": "1.0",
        "vendor": "cisco",
        "event_type": "link_down",
        "severity": "high",
    }
    assert "device_name" not in stream
    assert "interface_name" not in stream


@pytest.mark.asyncio
async def test_loki_query_builds_filters_and_returns_cursor() -> None:
    events = [
        _event(1, BASE_TIME + timedelta(seconds=2)),
        _event(2, BASE_TIME + timedelta(seconds=1)),
    ]
    captured_query: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_query.update(dict(request.url.params))
        values = [
            [str(int(event.timestamp.timestamp() * 1_000_000_000)), event.model_dump_json()]
            for event in events
        ]
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {"resultType": "streams", "result": [{"stream": {}, "values": values}]},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        storage = LokiLogStorage("http://loki:3100", client=client)
        page = await storage.query_events(
            EventQuery(
                start=BASE_TIME,
                end=BASE_TIME + timedelta(minutes=1),
                limit=1,
                severity=EventSeverity.HIGH,
                event_type=EventType.LINK_DOWN,
                vendor=EventVendor.CISCO,
                device_name="core-sw-01",
                interface_name="GigabitEthernet0/1",
            )
        )

    assert page.items == (events[0],)
    assert page.next_cursor is not None
    assert captured_query["direction"] == "backward"
    assert captured_query["limit"] == "2"
    assert captured_query["query"] == (
        '{job="network-events",severity="high",event_type="link_down",vendor="cisco"}'
        ' | json | device_name="core-sw-01" | interface_name="GigabitEthernet0/1"'
    )


@pytest.mark.asyncio
async def test_loki_query_hides_replayed_event_ids() -> None:
    event = _event(1)

    def handler(request: httpx.Request) -> httpx.Response:
        value = [str(int(event.timestamp.timestamp() * 1_000_000_000)), event.model_dump_json()]
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [{"stream": {}, "values": [value, value]}],
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page = await LokiLogStorage("http://loki:3100", client=client).query_events(
            EventQuery(
                start=BASE_TIME - timedelta(seconds=1),
                end=BASE_TIME + timedelta(seconds=1),
                limit=10,
            )
        )

    assert page.items == (event,)


@pytest.mark.asyncio
async def test_loki_rejects_invalid_cursor_before_network_request() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as client:
        storage = LokiLogStorage("http://loki:3100", client=client)
        with pytest.raises(InvalidCursorError):
            await storage.query_events(
                EventQuery(
                    start=BASE_TIME,
                    end=BASE_TIME + timedelta(minutes=1),
                    limit=10,
                    cursor="not-a-valid-cursor",
                )
            )
