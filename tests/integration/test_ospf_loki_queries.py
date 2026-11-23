"""Run against a disposable Loki using NETWORKSEC_TEST_LOKI_URL."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from app.parsers import parse_syslog
from app.schemas.event import NormalizedEvent
from app.storage.base import EventQuery
from app.storage.loki import LokiLogStorage


@pytest.mark.asyncio
async def test_provisioned_ospf_logql_on_loki_with_both_schema_versions() -> None:
    url = os.getenv("NETWORKSEC_TEST_LOKI_URL")
    if not url:
        pytest.skip("requires a disposable Loki and NETWORKSEC_TEST_LOKI_URL")
    provisioned = Path("infra/grafana/dashboards/ospf-observability.json")
    panels = json.loads(provisioned.read_text(encoding="utf-8"))["panels"]
    fixtures = Path("fixtures/logs")
    cisco = (fixtures / "cisco-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    mikrotik = (fixtures / "mikrotik-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    now = datetime.now(UTC)
    received = now - timedelta(seconds=1)
    parsed = [
        parse_syslog(raw, source_host=host, received_at=received).event
        for raw, host in [(cisco[0], "R2"), (cisco[1], "R2"), (mikrotik[3], "R1")]
    ]
    assert all(event is not None for event in parsed)
    first = parsed[0]
    assert first is not None
    legacy = first.model_dump(
        exclude={
            "routing_protocol",
            "neighbor_router_id",
            "previous_state",
            "current_state",
        }
    ) | {"schema_version": "1.0", "raw_message": "historical neighbor down"}
    events = [
        NormalizedEvent.model_validate(
            payload | {"timestamp": received - timedelta(milliseconds=index), "received_at": now}
        )
        for index, payload in enumerate(
            [event.model_dump() for event in parsed if event is not None] + [legacy]
        )
    ]
    start = str(int((now - timedelta(seconds=10)).timestamp() * 1_000_000_000))
    end = str(int(now.timestamp() * 1_000_000_000))

    async with httpx.AsyncClient(base_url=url, timeout=15) as client:
        storage = LokiLogStorage(url, client=client)
        for event in events:
            await storage.push_event(event)
        results = []
        for panel in panels:
            target = panel["targets"][0]
            expression = target["expr"].replace("$__range", "10s").replace("$__auto", "10s")
            if target["queryType"] == "instant":
                response = await client.get(
                    "/loki/api/v1/query", params={"query": expression, "time": end}
                )
            else:
                response = await client.get(
                    "/loki/api/v1/query_range",
                    params={"query": expression, "start": start, "end": end, "step": "1s"},
                )
            assert response.status_code == 200, (expression, response.text)
            assert response.json()["status"] == "success"
            results.append(response.json()["data"]["result"])

    down, full, timeline, severity, devices, logs = results
    assert float(down[0]["value"][1]) == 2
    assert float(full[0]["value"][1]) == 1
    assert {stream["metric"]["event_type"] for stream in timeline} == {
        "routing_neighbor_down",
        "routing_neighbor_up",
        "routing_neighbor_state_change",
    }
    assert sum(float(item["value"][1]) for item in severity) == 4
    assert {(row["metric"]["vendor"], row["metric"]["device_name"]) for row in devices} == {
        ("cisco", "R2"),
        ("mikrotik", "R1"),
    }
    queried = [json.loads(value[1]) for stream in logs for value in stream["values"]]
    assert {row["schema_version"] for row in queried} == {"1.0", "1.1"}


@pytest.mark.asyncio
async def test_qa_native_loki_deduplication_keeps_page_cursor() -> None:
    url = os.getenv("NETWORKSEC_TEST_LOKI_URL")
    if not url:
        pytest.skip("requires a disposable Loki and NETWORKSEC_TEST_LOKI_URL")
    raw = Path("fixtures/logs/cisco-ios.log").read_text(encoding="utf-8").splitlines()[2]
    host = "qa-loki-page-" + uuid4().hex
    base = datetime.now(UTC) - timedelta(minutes=3)
    template = parse_syslog(raw, received_at=base, source_host=host).event
    assert template is not None
    events = tuple(
        NormalizedEvent.model_validate(
            template.model_dump(exclude={"event_id"})
            | {
                "timestamp": base + timedelta(seconds=second),
                "received_at": base + timedelta(seconds=second),
                "raw_message": f"QA synthetic record {second}",
            }
        )
        for second in range(3)
    )
    replay = events[-1].model_copy(update={"received_at": base + timedelta(seconds=4)})
    query_bounds = {
        "start": base - timedelta(seconds=1),
        "end": base + timedelta(seconds=5),
        "device_name": host,
    }
    async with httpx.AsyncClient(base_url=url, timeout=15) as client:
        storage = LokiLogStorage(url, client=client)
        for event in (*events, replay):
            await storage.push_event(event)
        unpaged = await storage.query_events(EventQuery(**query_bounds, limit=10))
        assert [event.event_id for event in unpaged.items] == [
            event.event_id for event in events[::-1]
        ]
        paged = await storage.query_events(EventQuery(**query_bounds, limit=2))
        assert len(paged.items) == 2
        assert paged.next_cursor is not None
        last = await storage.query_events(
            EventQuery(**query_bounds, limit=2, cursor=paged.next_cursor)
        )
    assert last.items == (events[0],)
    assert last.next_cursor is None


@pytest.mark.asyncio
async def test_qa01_native_loki_pages_equal_timestamps_across_schema_streams() -> None:
    url = os.getenv("NETWORKSEC_TEST_LOKI_URL")
    if not url:
        pytest.skip("requires a disposable Loki and NETWORKSEC_TEST_LOKI_URL")
    cisco = Path("fixtures/logs/cisco-ios.log").read_text(encoding="utf-8").splitlines()[2]
    mikrotik = (
        Path("fixtures/logs/mikrotik-ospf-synthetic.log")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    base = datetime.now(UTC) - timedelta(minutes=3)
    host = "qa01-ties-" + uuid4().hex
    templates = [parse_syslog(raw, received_at=base).event for raw in (cisco, mikrotik)]
    events = []
    for index in range(30):
        template = templates[index % len(templates)]
        assert template is not None
        timestamp = base + timedelta(microseconds=index // 20)
        events.append(
            NormalizedEvent.model_validate(
                template.model_dump()
                | {
                    "device_name": host,
                    "timestamp": timestamp,
                    "received_at": timestamp,
                    "raw_message": f"QA-01 native tie observation {index}",
                }
            )
        )
    async with httpx.AsyncClient(base_url=url, timeout=15) as client:
        storage = LokiLogStorage(url, client=client)
        for event in sorted(events, key=lambda event: (event.timestamp, event.event_id)):
            await storage.push_event(event)
            if event.schema_version == "1.1":
                await storage.push_event(
                    event.model_copy(
                        update={"received_at": event.received_at + timedelta(seconds=1)}
                    )
                )

        for version in (None, "1.0", "1.1"):
            query = EventQuery(
                start=base,
                end=base + timedelta(seconds=1),
                limit=4,
                device_name=host,
                schema_version=version,
            )
            expected = sorted(
                (event for event in events if version is None or event.schema_version == version),
                key=lambda event: (event.timestamp, event.event_id),
                reverse=True,
            )
            actual = []
            for offset in range(0, len(expected), query.limit):
                page = await storage.query_events(query)
                assert page.items == tuple(expected[offset : offset + query.limit])
                actual.extend(page.items)
                query = replace(query, cursor=page.next_cursor)
            assert actual == expected and query.cursor is None
