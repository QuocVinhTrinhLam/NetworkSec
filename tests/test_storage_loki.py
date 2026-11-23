from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app.parsers import parse_syslog
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import EventQuery, InvalidCursorError, StorageError, StorageUnavailableError
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
                schema_version="1.0",
            )
        )

    assert page.items == (events[0],)
    assert page.next_cursor is not None
    assert captured_query["direction"] == "backward"
    assert captured_query["limit"] == "2"
    assert captured_query["query"] == (
        '{job="network-events",schema_version="1.0",severity="high",'
        'event_type="link_down",vendor="cisco"}'
        ' | json | device_name="core-sw-01" | interface_name="GigabitEthernet0/1"'
    )


@pytest.mark.asyncio
async def test_loki_writes_ospf_and_reads_mixed_schema_versions() -> None:
    fixture = Path("fixtures/logs/mikrotik-ospf-synthetic.log")
    raw = fixture.read_text(encoding="utf-8").splitlines()[0]
    ospf = parse_syslog(raw, received_at=BASE_TIME).event
    assert ospf is not None
    legacy = _event(1)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            stream = json.loads(request.content)["streams"][0]
            assert stream["stream"] == {
                "job": "network-events",
                "schema_version": "1.1",
                "vendor": "mikrotik",
                "event_type": "routing_neighbor_down",
                "severity": "low",
            }
            assert json.loads(stream["values"][0][1])["ospf_area"] == "0.0.0.0"
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {"values": [["1", legacy.model_dump_json()]]},
                        {"values": [["2", ospf.model_dump_json()], ["2", ospf.model_dump_json()]]},
                    ],
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        storage = LokiLogStorage("http://loki:3100", client=client)
        await storage.push_event(ospf)
        page = await storage.query_events(
            EventQuery(start=BASE_TIME, end=ospf.timestamp + timedelta(seconds=1), limit=10)
        )

    assert page.items == (ospf, legacy)


@pytest.mark.asyncio
async def test_loki_evidence_lookup_filters_by_json_event_id() -> None:
    event = _event(1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["query"] == (
            '{job="network-events"} | json | event_id="' + event.event_id + '"'
        )
        return httpx.Response(
            200,
            json={"status": "success", "data": {"result": []}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await LokiLogStorage("http://loki:3100", client=client).query_events(
            EventQuery(
                start=BASE_TIME,
                end=BASE_TIME + timedelta(seconds=1),
                limit=1,
                event_id=event.event_id,
            )
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


@pytest.mark.asyncio
async def test_qa_loki_timeout_and_empty_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ready":
            raise httpx.ReadTimeout("QA_FAKE_PRIVATE_DETAIL", request=request)
        assert request.url.params["direction"] == "backward"
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})

    query = EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=10)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        assert not await storage.ready()
        page = await storage.query_events(query)
        assert page.items == () and page.next_cursor is None

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("QA_FAKE_PRIVATE_DETAIL", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(timeout)) as client:
        with pytest.raises(StorageUnavailableError, match="^Loki is unavailable$"):
            await LokiLogStorage("http://mock.invalid", client=client).query_events(query)


@pytest.mark.asyncio
async def test_qa_loki_rejects_non_object_response_as_storage_error() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[]))
    ) as client:
        with pytest.raises(StorageError):
            await LokiLogStorage("http://mock.invalid", client=client).query_events(
                EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=10)
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        pytest.param(None, id="null-envelope"),
        pytest.param({}, id="missing-status"),
        pytest.param({"status": []}, id="invalid-status"),
        pytest.param({"status": "success"}, id="missing-data"),
        pytest.param({"status": "success", "data": []}, id="invalid-data"),
        pytest.param({"status": "success", "data": {}}, id="missing-result"),
        pytest.param({"status": "success", "data": {"result": None}}, id="null-result"),
        pytest.param({"status": "success", "data": {"result": {}}}, id="invalid-result"),
        pytest.param(
            {"status": "success", "data": {"resultType": "matrix", "result": []}},
            id="wrong-result-type",
        ),
        pytest.param({"status": "success", "data": {"result": [None]}}, id="invalid-stream"),
        pytest.param({"status": "success", "data": {"result": [{}]}}, id="missing-values"),
        pytest.param(
            {"status": "success", "data": {"result": [{"values": {}}]}}, id="invalid-values"
        ),
        pytest.param(
            {"status": "success", "data": {"result": [{"stream": [], "values": []}]}},
            id="invalid-labels",
        ),
        pytest.param(
            {"status": "success", "data": {"result": [{"values": [["1", {}]]}]}},
            id="non-text-entry",
        ),
        pytest.param(
            {"status": "success", "data": {"result": [{"values": [["upstream-marker", ""]]}]}},
            id="invalid-entry-timestamp",
        ),
    ],
)
async def test_qa03_malformed_nested_loki_responses_have_controlled_errors(body: object) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(body))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        with pytest.raises(
            StorageError, match="^Loki returned an invalid query response$"
        ) as error:
            await storage.query_events(
                EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=10)
            )
    assert error.value.__suppress_context__


@pytest.mark.asyncio
async def test_qa03_empty_streams_are_valid_results() -> None:
    body = {
        "status": "success",
        "data": {"resultType": "streams", "result": [{"stream": {}, "values": []}]},
    }
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    async with httpx.AsyncClient(transport=transport) as client:
        page = await LokiLogStorage("http://mock.invalid", client=client).query_events(
            EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=1)
        )
    assert page.items == () and page.next_cursor is None


@pytest.mark.asyncio
async def test_qa_loki_page_continues_when_replay_consumes_upstream_limit() -> None:
    newest = _event(3, BASE_TIME + timedelta(seconds=3))
    replay = newest.model_copy(update={"received_at": newest.received_at + timedelta(seconds=1)})
    sources = (newest, replay, _event(2, BASE_TIME + timedelta(seconds=2)), _event(1))

    def handler(request: httpx.Request) -> httpx.Response:
        values = [
            [str(int(event.timestamp.timestamp() * 1_000_000_000)), event.model_dump_json()]
            for event in sources[: int(request.url.params["limit"])]
        ]
        return httpx.Response(
            200, json={"status": "success", "data": {"result": [{"values": values}]}}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page = await LokiLogStorage("http://mock.invalid", client=client).query_events(
            EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=4), limit=2)
        )
    assert [event.event_id for event in page.items] == [newest.event_id, sources[2].event_id]
    assert page.next_cursor is not None


def _entry(event: NormalizedEvent) -> tuple[int, str]:
    seconds = int(event.timestamp.timestamp())
    return seconds * 1_000_000_000 + event.timestamp.microsecond * 1000, event.model_dump_json()


def _stream_handler(
    entries: list[tuple[int, str]], requests: list[tuple[int, int, int]]
) -> httpx.MockTransport:
    ordered = sorted(entries, key=lambda entry: entry[0], reverse=True)

    def handle(request: httpx.Request) -> httpx.Response:
        start, end, limit = (int(request.url.params[key]) for key in ("start", "end", "limit"))
        requests.append((start, end, limit))
        selected = [[str(ns), raw] for ns, raw in ordered if start <= ns < end][:limit]
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {"result": [{"values": selected[::2]}, {"values": selected[1::2]}]},
            },
        )

    return httpx.MockTransport(handle)


@pytest.mark.asyncio
async def test_qa03_valid_streams_page_mixed_schemas_past_replay_and_invalid_log() -> None:
    fixture = Path("fixtures/logs/mikrotik-ospf-synthetic.log")
    ospf = parse_syslog(fixture.read_text(encoding="utf-8").splitlines()[0]).event
    assert ospf is not None
    stamp = BASE_TIME + timedelta(seconds=1)
    normalized = NormalizedEvent.model_validate(
        ospf.model_dump() | {"timestamp": stamp, "received_at": stamp}
    )
    replay = normalized.model_copy(update={"received_at": stamp + timedelta(seconds=1)})
    legacy = _event(1)
    entries = [_entry(normalized), _entry(replay), (_entry(normalized)[0], "{"), _entry(legacy)]
    query = EventQuery(start=BASE_TIME, end=stamp + timedelta(seconds=1), limit=1)
    async with httpx.AsyncClient(transport=_stream_handler(entries, [])) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        first = await storage.query_events(query)
        assert first.items == (normalized,) and first.next_cursor
        last = await storage.query_events(replace(query, cursor=first.next_cursor))
    assert last.items == (legacy,) and last.next_cursor is None


@pytest.mark.asyncio
async def test_qa01_paginates_complete_timestamp_ties_in_fixed_id_order() -> None:
    stamp = BASE_TIME + timedelta(seconds=1, microseconds=1)
    tied = sorted((_event(index, stamp) for index in range(760)), key=lambda event: event.event_id)
    replay = tied[-1].model_copy(update={"received_at": stamp + timedelta(seconds=5)})
    older = _event(760)
    excluded_at_end = _event(761, stamp + timedelta(seconds=1))
    entries = [_entry(event) for event in (replay, *tied, older, excluded_at_end)]
    requests: list[tuple[int, int, int]] = []
    query = EventQuery(start=BASE_TIME, end=excluded_at_end.timestamp, limit=250)
    collected: list[NormalizedEvent] = []
    tokens: set[str] = set()
    async with httpx.AsyncClient(transport=_stream_handler(entries, requests)) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        for expected_size in (250, 250, 250, 11):
            page = await storage.query_events(query)
            collected.extend(page.items)
            assert len(page.items) == expected_size
            if page.next_cursor is not None:
                assert page.next_cursor not in tokens
                tokens.add(page.next_cursor)
            query = replace(query, cursor=page.next_cursor)
        assert query.cursor is None

    assert collected == [*reversed(tied), older]
    assert len(tokens) == 3
    assert len({len(token) for token in tokens}) == 1
    assert all(len(token) < 256 for token in tokens)
    assert all(limit <= 5000 for _, _, limit in requests)


@pytest.mark.asyncio
async def test_qa01_scans_older_batches_when_duplicates_and_invalid_lines_fill_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.storage.loki.MAX_LOKI_ENTRIES", 4)
    events = [_event(index, BASE_TIME + timedelta(seconds=index)) for index in range(4)]
    requests: list[tuple[int, int, int]] = []
    entries = [
        line
        for event in events
        for line in (_entry(event), _entry(event), (_entry(event)[0], "invalid schema payload"))
    ]
    query = EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=4), limit=3)
    async with httpx.AsyncClient(transport=_stream_handler(entries, requests)) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        page = await storage.query_events(query)
        assert page.items == tuple(events[:0:-1]) and page.next_cursor is not None
        last = await storage.query_events(replace(query, cursor=page.next_cursor))
    assert last.items == (events[0],) and last.next_cursor is None
    assert [end for _, end, _ in requests[:3]] == [
        _entry(events[3])[0] + 1_000_000_000,
        _entry(events[2])[0] + 1,
        _entry(events[1])[0] + 1,
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("query_budget", [2, 24], ids=["request-cap", "entry-cap"])
async def test_qa01_incomplete_timestamp_at_backend_limit_fails_explicitly(
    monkeypatch: pytest.MonkeyPatch, query_budget: int
) -> None:
    monkeypatch.setattr("app.storage.loki.MAX_LOKI_ENTRIES", 4)
    monkeypatch.setattr("app.storage.loki.MAX_PAGE_QUERIES", query_budget)
    requests: list[tuple[int, int, int]] = []
    entries = [_entry(_event(index)) for index in range(8)]
    async with httpx.AsyncClient(transport=_stream_handler(entries, requests)) as client:
        with pytest.raises(StorageError, match="Loki pagination"):
            await LokiLogStorage("http://mock.invalid", client=client).query_events(
                EventQuery(start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=1)
            )
    assert len(requests) == min(query_budget, 3)


def _token(body: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")


@pytest.mark.asyncio
async def test_qa01_resumes_legacy_cursor_with_gaps_in_timestamp_tie() -> None:
    events = sorted((_event(index) for index in range(6)), key=lambda event: event.event_id)
    already_returned = {events[1].event_id, events[4].event_id}
    legacy = _token({"timestamp_ns": _entry(events[0])[0], "seen_ids": list(already_returned)})
    query = EventQuery(
        start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=1, cursor=legacy
    )
    result: list[str] = []
    async with httpx.AsyncClient(
        transport=_stream_handler([_entry(e) for e in events], [])
    ) as client:
        storage = LokiLogStorage("http://mock.invalid", client=client)
        for _ in range(4):
            page = await storage.query_events(query)
            result.extend(event.event_id for event in page.items)
            query = replace(query, cursor=page.next_cursor)
    assert query.cursor is None
    assert result == [
        event.event_id for event in reversed(events) if event.event_id not in already_returned
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["expired", "beyond-end", "bad-id", "bad-timestamp", "bad-legacy"])
async def test_qa01_rejects_out_of_window_and_malformed_cursors(mode: str) -> None:
    ns, _ = _entry(_event(0))
    body: dict[str, object] = {"timestamp_ns": ns, "before_id": "1" * 64}
    if mode == "expired":
        body["timestamp_ns"] = ns - 1
    elif mode == "beyond-end":
        body["timestamp_ns"] = ns + 1_000_000_000
    elif mode == "bad-id":
        body["before_id"] = "x" * 64
    elif mode == "bad-timestamp":
        body["timestamp_ns"] = str(ns)
    else:
        body = {"timestamp_ns": ns, "seen_ids": "1" * 64}
    requests: list[tuple[int, int, int]] = []
    async with httpx.AsyncClient(transport=_stream_handler([], requests)) as client:
        with pytest.raises(InvalidCursorError):
            await LokiLogStorage("http://mock.invalid", client=client).query_events(
                EventQuery(
                    start=BASE_TIME,
                    end=BASE_TIME + timedelta(seconds=1),
                    limit=10,
                    cursor=_token(body),
                )
            )
    assert not requests


@pytest.mark.asyncio
async def test_qa01_valid_cursor_returns_empty_without_repeating_after_retention() -> None:
    event = _event(1)
    cursor = _token({"timestamp_ns": _entry(event)[0], "before_id": event.event_id})
    requests: list[tuple[int, int, int]] = []
    async with httpx.AsyncClient(transport=_stream_handler([], requests)) as client:
        page = await LokiLogStorage("http://mock.invalid", client=client).query_events(
            EventQuery(
                start=BASE_TIME, end=BASE_TIME + timedelta(seconds=1), limit=1, cursor=cursor
            )
        )
    assert not page.items and page.next_cursor is None
    assert len(requests) == 1
