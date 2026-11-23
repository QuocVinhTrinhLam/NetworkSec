"""Component integration tests for the restart-safe processing worker."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from app.parsers import parse_syslog
from app.processor import worker as worker_module
from app.processor.state import ProcessorStateStore
from app.processor.worker import MAX_ENVELOPE_BYTES, ProcessingWorker
from app.schemas.correlation import AggregatedAlert, OspfCorrelationSnapshot
from app.schemas.event import EventType, NormalizedEvent
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter
from app.storage.base import StorageError

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
        self.ospf: dict[str, OspfCorrelationSnapshot] = {}
        self.fail_next = False

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AggregatedAlert:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected PostgreSQL failure")
        self.alerts[alert.aggregate_id] = alert
        self.event_ids.add(event.event_id)
        return alert

    def apply_ospf_snapshot(self, snapshot: OspfCorrelationSnapshot) -> bool:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected PostgreSQL failure")
        old = self.ospf.get(snapshot.adjacency_id)
        if old is not None and old.revision >= snapshot.revision:
            return False
        self.ospf[snapshot.adjacency_id] = snapshot
        return True


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
    correlation_config: Path = Path("config/correlation_rules.yaml"),
) -> ProcessingWorker:
    state = ProcessorStateStore(root / "processor-state.db")
    state.initialize()
    correlation = CorrelationEngine.from_files(root / "correlation.db", correlation_config)
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
async def test_ospf_transitions_reach_event_storage_through_the_worker(tmp_path: Path) -> None:
    fixtures = Path("fixtures/logs")
    cisco = (fixtures / "cisco-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    mikrotik = (fixtures / "mikrotik-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    records = []
    for raw, priority, host in ((mikrotik[0], "<134>", "R1"), (cisco[1], "<189>", "R2")):
        envelope = json.loads(_envelope(1))
        envelope.update(raw_message=raw, parse_message=raw.removeprefix(priority), source_host=host)
        records.append(json.dumps(envelope))
    spool = tmp_path / "processor.jsonl"
    spool.write_text("\n".join(records) + "\n", encoding="utf-8")
    logs = RecordingLogs()
    alerts = RecordingAlerts()

    await _drain(_worker(tmp_path, logs, alerts), 2)
    await _drain(_worker(tmp_path, logs, alerts), 0)

    assert [event.event_type for event in logs.events.values()] == [
        EventType.ROUTING_NEIGHBOR_DOWN,
        EventType.ROUTING_NEIGHBOR_UP,
    ]
    assert all(event.schema_version == "1.1" for event in logs.events.values())
    assert not alerts.alerts


@pytest.mark.asyncio
async def test_ospf_journal_recovers_through_worker_retry_and_restart(tmp_path: Path) -> None:
    config_file = tmp_path / "rules.yaml"
    config = yaml.safe_load(Path("config/correlation_rules.yaml").read_text(encoding="utf-8"))
    config["ospf"]["links"] = [
        {
            "id": "r1-r2",
            "area": "0.0.0.0",
            "endpoints": [
                {"device_name": "R1", "interface_name": "ether3", "router_id": "192.0.2.1"},
                {
                    "device_name": "R2",
                    "interface_name": "GigabitEthernet0/1",
                    "router_id": "192.0.2.2",
                },
            ],
        }
    ]
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")
    fixtures = Path("fixtures/logs")
    cisco = (fixtures / "cisco-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    mikrotik = (fixtures / "mikrotik-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
    r1_full = mikrotik[1].replace("Nov 23 19:00:05", "2026-11-23T19:00:06+07:00")
    records = []
    for raw, host in ((mikrotik[0], "R1"), (cisco[0], "R2"), (cisco[1], "R2"), (r1_full, "R1")):
        envelope = json.loads(_envelope(1))
        envelope.update(
            received_at="2026-11-23T12:00:08Z",
            raw_message=raw,
            parse_message=raw.split(">", 1)[-1] if raw.startswith("<") else raw,
            source_host=host,
        )
        records.append(json.dumps(envelope))
    spool = tmp_path / "processor.jsonl"
    spool.write_text("\n".join(records) + "\n", encoding="utf-8")
    logs = RecordingLogs()
    alerts = RecordingAlerts()
    logs.fail_next = True
    first_worker = _worker(tmp_path, logs, alerts, config_file)

    with pytest.raises(RuntimeError, match="injected Loki failure"):
        await first_worker.process_once()
    assert not logs.events
    (key,) = first_worker.correlation.store.list_ospf_adjacencies()
    saved = first_worker.correlation.store.ospf_snapshot(key)
    assert saved.incidents[0].recovered_at is None
    assert not alerts.ospf

    alerts.fail_next = True
    with pytest.raises(RuntimeError, match="injected PostgreSQL failure"):
        await first_worker.process_once()
    assert len(logs.events) == 1
    assert not alerts.ospf
    health = first_worker.state.health()
    assert health is not None and health.processed_count == 0

    restarted = _worker(tmp_path, logs, alerts, config_file)
    assert await restarted.process_once()
    assert restarted.correlation.store.ospf_snapshot(key) == saved
    assert await restarted.process_once()
    assert await restarted.process_once()
    assert restarted.correlation.store.ospf_snapshot(key).incidents[0].recovered_at is None
    await _drain(restarted, 1)
    final = restarted.correlation.store.ospf_snapshot(key)
    (incident,) = final.incidents
    assert incident.incident_id == saved.incidents[0].incident_id
    assert incident.recovered_at == datetime(2026, 11, 23, 12, 0, 6, tzinfo=UTC)
    assert set(incident.event_ids) == set(logs.events)
    assert not alerts.alerts
    assert alerts.ospf == {final.adjacency_id: final}

    # The Phase 2 journal can already be checkpointed when PostgreSQL first needs it.
    empty_backend = RecordingAlerts()
    backfill = _worker(tmp_path, logs, empty_backend, config_file)
    assert not await backfill.process_once()
    assert empty_backend.ospf == {final.adjacency_id: final}


@pytest.mark.asyncio
async def test_ospf_backfill_requires_receipts_for_its_evidence(tmp_path: Path) -> None:
    alerts = RecordingAlerts()
    worker = _worker(tmp_path, RecordingLogs(), alerts)
    fixture = Path("fixtures/logs/mikrotik-ospf-synthetic.log")
    raw = fixture.read_text(encoding="utf-8").splitlines()[0]
    event = parse_syslog(raw, received_at=datetime(2026, 11, 23, 12, tzinfo=UTC)).event
    assert event is not None
    assert worker.correlation.process(event).ospf is not None
    with pytest.raises(StorageError, match="without processor receipts"):
        await worker.process_once()
    assert not alerts.ospf
    health = worker.state.health()
    assert health is not None and health.status == "blocked"


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


@pytest.mark.asyncio
async def test_qa_unexpected_parser_fault_keeps_offset_and_marks_worker_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, alerts = RecordingLogs(), RecordingAlerts()
    worker = _worker(tmp_path, logs, alerts)
    worker.spool_path.write_bytes(_envelope(1) + _envelope(2))
    assert await worker.process_once()

    def unexpected(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic parser fault")

    with monkeypatch.context() as patched:
        patched.setattr(worker_module, "parse_syslog", unexpected)
        with pytest.raises(RuntimeError, match="synthetic parser fault"):
            await worker.process_once()
        health_at_failure = worker.state.health()
    await _drain(_worker(tmp_path, logs, alerts), 1)
    assert len(logs.events) == 2
    assert health_at_failure is not None and health_at_failure.status == "blocked"


@pytest.mark.asyncio
async def test_qa04_parser_fault_survives_idle_and_restart_until_record_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs, alerts = RecordingLogs(), RecordingAlerts()
    worker = _worker(tmp_path, logs, alerts)
    worker.spool_path.write_bytes(_envelope(1) + _envelope(2))
    assert await worker.process_once()
    before = worker.state.health()
    assert before is not None and before.processed_count == 1

    def unexpected(*args: object, **kwargs: object) -> None:
        raise RuntimeError("test-record-private-marker")

    with monkeypatch.context() as patched:
        patched.setattr(worker_module, "parse_syslog", unexpected)
        for _ in range(2):
            with pytest.raises(RuntimeError, match="test-record-private-marker"):
                await worker.process_once()
            blocked = worker.state.health()
            assert blocked is not None and blocked.status == "blocked"
            assert blocked.detail == "RuntimeError: syslog parser failed"
            assert blocked.last_success_at == before.last_success_at
            assert (blocked.processed_count, blocked.dead_letter_count) == (1, 0)
            worker = _worker(tmp_path, logs, alerts)
            assert worker.state.health() == blocked

        spool = worker.spool_path
        moved = spool.rename(tmp_path / "pending-spool.jsonl")
        assert not await worker.process_once()
        assert worker.state.health() == blocked
        moved.rename(spool)

    await _drain(worker, 1)
    recovered = worker.state.health()
    assert recovered is not None and recovered.status == "healthy" and recovered.detail is None
    assert (recovered.processed_count, recovered.dead_letter_count, len(logs.events)) == (2, 0, 2)


@pytest.mark.asyncio
async def test_qa04_idle_reconciliation_clears_its_own_block_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _worker(tmp_path, RecordingLogs(), RecordingAlerts())
    reconciliation = worker._reconcile_ospf

    async def fail_once() -> None:
        monkeypatch.setattr(worker, "_reconcile_ospf", reconciliation)
        raise StorageError("synthetic reconciliation failure")

    monkeypatch.setattr(worker, "_reconcile_ospf", fail_once)
    with pytest.raises(StorageError, match="synthetic reconciliation failure"):
        await worker.process_once()
    blocked = worker.state.health()
    assert blocked is not None and blocked.status == "blocked"
    assert not await worker.process_once()
    recovered = worker.state.health()
    assert recovered is not None and recovered.status == "healthy"
