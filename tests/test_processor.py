"""Component integration tests for the restart-safe processing worker."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.processor.state import ProcessorStateStore
from app.processor.worker import MAX_ENVELOPE_BYTES, ProcessingWorker
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import NormalizedEvent
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter

BASE_TIME = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


class RecordingLogs:
    def __init__(self) -> None:
        self.events: dict[str, NormalizedEvent] = {}
        self.fail_next = False

    async def push_event(self, event: NormalizedEvent) -> None:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected Loki failure")
        self.events[event.event_id] = event


class RecordingAlerts:
    def __init__(self) -> None:
        self.alerts: dict[str, AggregatedAlert] = {}
        self.event_ids: set[str] = set()
        self.fail_next = False

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AggregatedAlert:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected PostgreSQL failure")
        self.alerts[alert.aggregate_id] = alert
        self.event_ids.add(event.event_id)
        return alert


def _envelope(sequence: int) -> bytes:
    timestamp = BASE_TIME + timedelta(milliseconds=500 * sequence)
    state = "up" if sequence % 2 == 0 else "down"
    raw = (
        f"Nov 20 {timestamp:%H:%M:%S}.{timestamp.microsecond // 1000:03d}: "
        f"%LINK-3-UPDOWN: Interface Gi0/1, changed state to {state}"
    )
    document = {
        "schema_version": "1.0",
        "received_at": timestamp.isoformat(),
        "source_host": "core-sw-01",
        "source_ip": "192.0.2.10",
        "raw_message": raw,
        "parse_message": raw,
    }
    return json.dumps(document, separators=(",", ":")).encode() + b"\n"


def _worker(
    root: Path,
    logs: RecordingLogs,
    alerts: RecordingAlerts,
) -> ProcessingWorker:
    state = ProcessorStateStore(root / "processor-state.db")
    state.initialize()
    correlation = CorrelationEngine.from_files(
        root / "correlation.db", Path("config/correlation_rules.yaml")
    )
    return ProcessingWorker(
        spool_path=root / "processor.jsonl",
        state=state,
        correlation=correlation,
        logs=logs,  # type: ignore[arg-type]
        writer=StorageWriter(logs, alerts),  # type: ignore[arg-type]
        source_timezone=UTC,
    )


async def _drain(worker: ProcessingWorker, count: int) -> None:
    for _ in range(count):
        assert await worker.process_once() is True
    assert await worker.process_once() is False


@pytest.mark.asyncio
async def test_100_link_events_are_traceable_and_replay_safe(tmp_path: Path) -> None:
    spool = tmp_path / "processor.jsonl"
    records = b"".join(_envelope(sequence) for sequence in range(100))
    spool.write_bytes(records)
    logs = RecordingLogs()
    alerts = RecordingAlerts()
    worker = _worker(tmp_path, logs, alerts)

    await _drain(worker, 100)

    correlated = worker.correlation.store.list_alerts()
    assert len(correlated) == 1
    aggregate = correlated[0]
    assert aggregate.count == 100
    traces = worker.correlation.store.trace_events(aggregate.aggregate_id)
    assert len(traces) == 100
    assert len(logs.events) == 100
    assert alerts.event_ids == {trace.event_id for trace in traces}
    assert all(trace.raw_message == trace.event.raw_message for trace in traces)
    with worker.state.connect() as connection:
        receipts = connection.execute(
            "SELECT event_id, start_offset, end_offset FROM processor_event_receipts"
        ).fetchall()
    assert len(receipts) == 100
    assert {row["event_id"] for row in receipts} == {trace.event_id for trace in traces}
    assert all(row["end_offset"] > row["start_offset"] for row in receipts)

    first_claim = worker.correlation.store.claim_notification(
        aggregate.aggregate_id, BASE_TIME + timedelta(minutes=1)
    )
    duplicate_claim = worker.correlation.store.claim_notification(
        aggregate.aggregate_id, BASE_TIME + timedelta(minutes=1, seconds=1)
    )
    assert first_claim.allowed is True
    assert duplicate_claim.allowed is False

    with spool.open("ab") as destination:
        destination.write(records)
    await _drain(worker, 100)

    replayed = worker.correlation.store.get_alert(aggregate.aggregate_id)
    assert replayed is not None
    assert replayed.count == 100
    assert len(worker.correlation.store.trace_events(aggregate.aggregate_id)) == 100
    assert len(logs.events) == 100
    assert len(alerts.event_ids) == 100


@pytest.mark.asyncio
async def test_restart_resumes_from_durable_checkpoint(tmp_path: Path) -> None:
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(b"".join(_envelope(sequence) for sequence in range(100)))
    logs = RecordingLogs()
    alerts = RecordingAlerts()
    first_worker = _worker(tmp_path, logs, alerts)

    for _ in range(40):
        assert await first_worker.process_once() is True

    restarted_worker = _worker(tmp_path, logs, alerts)
    await _drain(restarted_worker, 60)

    aggregates = restarted_worker.correlation.store.list_alerts()
    assert len(aggregates) == 1
    assert aggregates[0].count == 100
    assert len(restarted_worker.correlation.store.trace_events(aggregates[0].aggregate_id)) == 100


@pytest.mark.asyncio
async def test_failed_storage_write_does_not_advance_checkpoint(tmp_path: Path) -> None:
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(_envelope(1))
    logs = RecordingLogs()
    logs.fail_next = True
    alerts = RecordingAlerts()
    worker = _worker(tmp_path, logs, alerts)

    with pytest.raises(RuntimeError, match="injected Loki failure"):
        await worker.process_once()

    with worker.state.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM processor_checkpoints").fetchone()[0] == 0
    assert worker.state.health() is not None
    assert worker.state.health().status == "blocked"  # type: ignore[union-attr]

    assert await worker.process_once() is True
    aggregate = worker.correlation.store.list_alerts()[0]
    assert aggregate.count == 1
    assert len(worker.correlation.store.trace_events(aggregate.aggregate_id)) == 1
    assert len(logs.events) == 1
    assert len(alerts.event_ids) == 1


@pytest.mark.asyncio
async def test_postgres_failure_retries_after_loki_without_double_count(tmp_path: Path) -> None:
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(_envelope(1))
    logs = RecordingLogs()
    alerts = RecordingAlerts()
    alerts.fail_next = True
    worker = _worker(tmp_path, logs, alerts)

    with pytest.raises(RuntimeError, match="injected PostgreSQL failure"):
        await worker.process_once()

    with worker.state.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM processor_checkpoints").fetchone()[0] == 0
    assert len(logs.events) == 1
    assert not alerts.event_ids

    assert await worker.process_once() is True
    aggregate = worker.correlation.store.list_alerts()[0]
    assert aggregate.count == 1
    assert len(worker.correlation.store.trace_events(aggregate.aggregate_id)) == 1
    assert len(logs.events) == 1
    assert len(alerts.event_ids) == 1


@pytest.mark.asyncio
async def test_malformed_record_is_dead_lettered_atomically(tmp_path: Path) -> None:
    spool = tmp_path / "processor.jsonl"
    malformed = b'{"schema_version":"1.0","raw_message":}\n'
    spool.write_bytes(malformed)
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())

    assert await worker.process_once() is True
    assert await worker.process_once() is False

    with worker.state.connect() as connection:
        dead_letter = connection.execute(
            "SELECT reason, start_offset, end_offset, record FROM processor_dead_letters"
        ).fetchone()
        checkpoint = connection.execute("SELECT byte_offset FROM processor_checkpoints").fetchone()
    assert dead_letter is not None
    assert dead_letter["reason"] == "envelope_invalid_json"
    assert dead_letter["start_offset"] == 0
    assert dead_letter["end_offset"] == len(malformed)
    assert bytes(dead_letter["record"]) == malformed
    assert checkpoint["byte_offset"] == len(malformed)
    assert spool.read_bytes() == malformed


@pytest.mark.asyncio
async def test_partial_record_waits_for_newline_without_checkpoint(tmp_path: Path) -> None:
    complete = _envelope(1)
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(complete[:-1])
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())

    assert await worker.process_once() is False
    with worker.state.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM processor_checkpoints").fetchone()[0] == 0

    with spool.open("ab") as destination:
        destination.write(b"\n")
    assert await worker.process_once() is True


@pytest.mark.asyncio
async def test_unknown_event_uses_dead_letter_and_processing_continues(tmp_path: Path) -> None:
    unknown = {
        "schema_version": "1.0",
        "received_at": BASE_TIME.isoformat(),
        "source_host": "core-sw-01",
        "source_ip": "192.0.2.10",
        "raw_message": "verified-but-unsupported-message",
        "parse_message": "verified-but-unsupported-message",
    }
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(json.dumps(unknown).encode() + b"\n" + _envelope(2))
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())

    assert await worker.process_once() is True
    assert await worker.process_once() is True

    with worker.state.connect() as connection:
        row = connection.execute("SELECT reason FROM processor_dead_letters").fetchone()
    assert row["reason"] == "parse_unknown:unsupported_format"
    assert worker.correlation.store.list_alerts()[0].count == 1


@pytest.mark.asyncio
async def test_oversized_corrupt_record_is_bounded_and_skipped(tmp_path: Path) -> None:
    oversized = b"x" * (MAX_ENVELOPE_BYTES + 100) + b"\n"
    spool = tmp_path / "processor.jsonl"
    spool.write_bytes(oversized + _envelope(2))
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())

    assert await worker.process_once() is True
    assert await worker.process_once() is True

    with worker.state.connect() as connection:
        row = connection.execute(
            """
            SELECT reason, start_offset, end_offset, length(record) AS stored
            FROM processor_dead_letters
            """
        ).fetchone()
    assert row["reason"] == "envelope_too_large"
    assert row["start_offset"] == 0
    assert row["end_offset"] == len(oversized)
    assert row["stored"] == MAX_ENVELOPE_BYTES + 1
    assert worker.correlation.store.list_alerts()[0].count == 1


@pytest.mark.asyncio
async def test_run_forever_stops_cleanly_while_idle(tmp_path: Path) -> None:
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run_forever(stop))

    await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, timeout=1)

    snapshot = worker.state.health()
    assert snapshot is not None
    assert snapshot.status == "healthy"
