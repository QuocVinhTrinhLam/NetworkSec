"""Bounded, offline QA benchmark. Run from the repository with PYTHONPATH=."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import time
from datetime import UTC
from pathlib import Path
from typing import Any

from qa_synthetic import R1, link_line, routeros_ospf, spool_line, timestamp

from app.benchmark.runner import _rss_bytes
from app.parsers import parse_syslog
from app.processor.state import ProcessorStateStore
from app.processor.worker import ProcessingWorker
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import NormalizedEvent
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter

RULES = Path("config/correlation_rules.yaml")


class MemoryLogs:
    def __init__(self) -> None:
        self.attempts = 0
        self.events: set[str] = set()

    async def push_event(self, event: NormalizedEvent) -> None:
        self.attempts += 1
        self.events.add(event.event_id)


class MemoryAlerts:
    def __init__(self) -> None:
        self.attempts = 0
        self.event_ids: set[str] = set()
        self.rows: dict[str, AggregatedAlert] = {}

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> None:
        self.attempts += 1
        self.rows[alert.aggregate_id] = alert
        self.event_ids.add(event.event_id)


def stage(latencies: list[float], wall: float, cpu: float) -> dict[str, Any]:
    samples = sorted(latencies)
    return {
        "events_per_s": round(len(latencies) / wall, 2),
        "duration_s": round(wall, 4),
        "cpu_core_pct": round(100 * cpu / wall, 1),
        "p50_ms": round(samples[math.ceil(0.50 * len(samples)) - 1] * 1000, 3),
        "p95_ms": round(samples[math.ceil(0.95 * len(samples)) - 1] * 1000, 3),
        "rss_mib_at_stage_end": round(_rss_bytes() / (1024 * 1024), 1),
    }


async def benchmark(root: Path, count: int) -> dict[str, Any]:
    path = root / f"link-{count}"
    path.mkdir()
    lines = [link_line(index) for index in range(count)]
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    samples: list[float] = []
    events: list[NormalizedEvent] = []
    for observed, raw in lines:
        started = time.perf_counter()
        result = parse_syslog(raw, received_at=observed, source_host="qa-switch")
        samples.append(time.perf_counter() - started)
        assert result.event is not None
        events.append(result.event)
    parsing = stage(samples, time.perf_counter() - wall_start, time.process_time() - cpu_start)

    engine = CorrelationEngine.from_files(path / "correlation-measurement.db", RULES)
    samples.clear()
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    for event in events:
        started = time.perf_counter()
        assert engine.process(event).matched
        samples.append(time.perf_counter() - started)
    correlation = stage(samples, time.perf_counter() - wall_start, time.process_time() - cpu_start)

    spool = path / "spool.jsonl"
    duplicates = lines[: count // 10]
    with spool.open("wb") as output:
        for observed, raw in lines + duplicates:
            output.write(spool_line(raw, observed))
    state = ProcessorStateStore(path / "processor.sqlite")
    state.initialize()
    logs, alerts = MemoryLogs(), MemoryAlerts()
    worker = ProcessingWorker(
        spool_path=spool,
        state=state,
        correlation=CorrelationEngine.from_files(path / "worker-correlation.sqlite", RULES),
        logs=logs,  # type: ignore[arg-type]
        writer=StorageWriter(logs, alerts),  # type: ignore[arg-type]
        source_timezone=UTC,
    )
    samples.clear()
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    for _ in range(len(lines) + len(duplicates)):
        started = time.perf_counter()
        assert await worker.process_once()
        samples.append(time.perf_counter() - started)
    end_to_end = stage(samples, time.perf_counter() - wall_start, time.process_time() - cpu_start)
    assert not await worker.process_once()
    health = state.health()
    assert health is not None and health.dead_letter_count == 0
    assert len(logs.events) == len(alerts.event_ids) == count
    assert sum(row.count for row in alerts.rows.values()) == count
    assert logs.attempts == alerts.attempts == len(lines) + len(duplicates)
    return {
        "workload": "link-state",
        "unique_inputs": count,
        "duplicates": len(duplicates),
        "parse": parsing,
        "correlate": correlation,
        "worker": end_to_end,
        "loki_fake_writes": logs.attempts,
        "postgres_fake_writes": alerts.attempts,
        "unique_event_ids": len(logs.events),
    }


def ospf_correlation(root: Path, count: int) -> dict[str, Any]:
    engine = CorrelationEngine.from_files(root / f"ospf-{count}.db", RULES)
    observations = [
        parse_syslog(
            routeros_ospf(index / 1000, "Full", "Down"),
            received_at=timestamp(index / 1000),
            source_host=R1,
        ).event
        for index in range(count)
    ]
    samples: list[float] = []
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    for index, event in enumerate(observations, start=1):
        assert event is not None
        started = time.perf_counter()
        result = engine.process(event).ospf
        samples.append(time.perf_counter() - started)
        assert result is not None and len(result.incidents) == 1
        assert len(result.incidents[0].evidence) == index
    return {
        "workload": "ospf-single-adjacency-repeated-down",
        "unique_inputs": count,
        "correlate": stage(
            samples, time.perf_counter() - wall_start, time.process_time() - cpu_start
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("new_directory", type=Path, help="dedicated path that does not yet exist")
    parser.add_argument("--limit", type=int, choices=(100, 1000, 10000), default=1000)
    options = parser.parse_args()
    root = options.new_directory
    root.mkdir()
    for count in (100, 1000):
        if count <= options.limit:
            print(json.dumps(ospf_correlation(root, count)), flush=True)
    for count in (100, 1000, 10000):
        if count <= options.limit:
            print(json.dumps(asyncio.run(benchmark(root, count))), flush=True)


if __name__ == "__main__":
    main()
