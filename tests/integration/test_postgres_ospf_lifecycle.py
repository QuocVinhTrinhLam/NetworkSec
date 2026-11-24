"""Run with NETWORKSEC_TEST_POSTGRES_DSN pointing to a disposable PostgreSQL database."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

import psycopg
import pytest
import yaml
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from app.bot.notification_models import OspfNotificationKind, TelegramSendDeferred
from app.bot.ospf import OspfNotificationWorker
from app.config import Settings
from app.main import create_app
from app.parsers import parse_syslog
from app.processor.state import ProcessorStateStore
from app.processor.worker import ProcessingWorker
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import OspfCorrelationSnapshot
from app.schemas.event import EventSeverity, NormalizedEvent
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter
from app.storage.backend import PostgresBackendStorage
from app.storage.base import AlertQuery, StorageError
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage
from app.web.auth import hash_password

MIGRATIONS = Path("migrations/postgresql")
BASE_TIME = datetime(2026, 11, 23, 12, tzinfo=UTC)
FIXTURES = Path("fixtures/logs")
CISCO = (FIXTURES / "cisco-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
MIKROTIK = (FIXTURES / "mikrotik-ospf-synthetic.log").read_text(encoding="utf-8").splitlines()
MIKROTIK_DUAL = (
    (FIXTURES / "mikrotik-ospf-dual-synthetic.log").read_text(encoding="utf-8").splitlines()
)


@pytest.fixture
def isolated_dsn() -> str:
    dsn = os.getenv("NETWORKSEC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires a disposable PostgreSQL database and NETWORKSEC_TEST_POSTGRES_DSN")
    schema = "networksec_test_" + uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    return make_conninfo(dsn, options=f"-c search_path={schema}")


@pytest.fixture
def storage(isolated_dsn: str) -> PostgresAlertStorage:
    backend = PostgresAlertStorage(isolated_dsn, MIGRATIONS)
    backend.migrate()
    return backend


@pytest.fixture
def ospf_rules_path(tmp_path: Path) -> Path:
    config = yaml.safe_load(Path("config/correlation_rules.yaml").read_text(encoding="utf-8"))
    config["ospf"]["links"] = [
        {
            "id": "test-transit",
            "area": "0.0.0.0",
            "endpoints": [
                {"router_id": "192.0.2.1", "device_name": "R1", "interface_name": "ether3"},
                {
                    "router_id": "192.0.2.2",
                    "device_name": "R2",
                    "interface_name": "GigabitEthernet0/1",
                },
            ],
        }
    ]
    rules = tmp_path / "rules.yaml"
    rules.write_text(yaml.safe_dump(config), encoding="utf-8")
    return rules


@pytest.fixture
def observe(tmp_path: Path, ospf_rules_path: Path) -> Callable[[str, int], OspfCorrelationSnapshot]:
    db = tmp_path / "correlation.db"

    def process(kind: str, second: int) -> OspfCorrelationSnapshot:
        hostname = "R1" if kind.startswith("r1") else "R2"
        packet = {
            "r1-down": MIKROTIK[0],
            "r1-full": MIKROTIK[1],
            "r2-down": CISCO[0],
            "r2-full": CISCO[1],
        }[kind]
        event = parse_syslog(packet, received_at=BASE_TIME, source_host=hostname).event
        assert event is not None
        timestamp = BASE_TIME + timedelta(seconds=second)
        retimed = NormalizedEvent.model_validate(
            event.model_dump()
            | {
                "timestamp": timestamp,
                "received_at": timestamp + timedelta(seconds=1),
                "raw_message": f"{packet} [synthetic test time {second}]",
            }
        )
        # Each call creates a fresh engine on the same journal, as on worker restart.
        projection = CorrelationEngine.from_files(db, ospf_rules_path).process(retimed).ospf
        assert projection is not None
        return projection

    return process


def test_acknowledged_alert_resolves_once_and_stays_visible_before_recovery(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    opened = observe("r1-down", 10)
    incident_id = opened.incidents[0].incident_id
    assert storage.apply_ospf_snapshot(opened)
    assert not storage.apply_ospf_snapshot(opened)
    assert storage.get_ospf_incident(incident_id) is not None
    acknowledged = storage.acknowledge(incident_id, "NOC", "check transit")
    assert acknowledged is not None
    assert storage.acknowledge(incident_id, "retry", None) == acknowledged
    aged = AlertQuery(
        start=BASE_TIME + timedelta(days=2),
        end=BASE_TIME + timedelta(days=3),
        page=1,
        page_size=25,
        include_active_before_start=True,
    )
    assert storage.query_alerts(aged).items == (acknowledged,)

    assert storage.apply_ospf_snapshot(observe("r1-full", 10))
    assert storage.get_alert(incident_id).status is AlertLifecycleStatus.ACKNOWLEDGED
    recovered = observe("r1-full", 20)
    assert storage.apply_ospf_snapshot(recovered)
    record = storage.get_alert(incident_id)
    assert record is not None
    assert record.status is AlertLifecycleStatus.RESOLVED
    assert (record.acknowledged_by, record.acknowledged_at, record.note) == (
        "NOC",
        acknowledged.acknowledged_at,
        "check transit",
    )
    assert record.status_changed_by == "ospf-correlation"
    assert storage.query_alerts(aged).total == 0
    evidence = storage.get_ospf_incident(incident_id)
    assert evidence is not None
    assert evidence.technical_recovered_at == BASE_TIME + timedelta(seconds=20)
    assert tuple(ref.event_id for ref in evidence.event_refs) == recovered.incidents[0].event_ids
    assert {str(ref.reporter_router_id) for ref in evidence.event_refs} == {"192.0.2.1"}
    assert evidence.reporters == recovered.incidents[0].reporters
    history_after_recovery = storage.get_alert_history(incident_id)
    assert storage.acknowledge(incident_id, "late ACK", "ignored after Full") == record
    assert storage.get_ospf_incident(incident_id) == evidence
    assert storage.get_alert_history(incident_id) == history_after_recovery
    assert not storage.apply_ospf_snapshot(recovered)
    assert not storage.apply_ospf_snapshot(opened)
    assert storage.apply_ospf_snapshot(observe("r1-full", 21))
    assert storage.get_alert(incident_id) == record
    assert [
        (item.status.value, item.source) for item in storage.get_alert_history(incident_id)
    ] == [
        ("new", "system"),
        ("acknowledged", "operator"),
        ("resolved", "ospf_recovery"),
    ]


def test_manual_resolution_survives_later_recovery_and_reassessment(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    opened = observe("r1-down", 1)
    incident_id = opened.incidents[0].incident_id
    storage.apply_ospf_snapshot(opened)
    manual = storage.update_status(incident_id, "resolved", "Operator", "field repair")
    assert manual is not None
    assert storage.apply_ospf_snapshot(observe("r1-full", 10))
    evidence = storage.get_ospf_incident(incident_id)
    assert evidence.technical_recovered_at == BASE_TIME + timedelta(seconds=10)
    assert len(evidence.event_refs) == 2
    assert storage.apply_ospf_snapshot(observe("r2-down", 5))
    assert storage.get_ospf_incident(incident_id).technical_recovered_at is None
    assert storage.apply_ospf_snapshot(observe("r2-full", 15))
    record = storage.get_alert(incident_id)
    assert record is not None
    assert (record.status, record.status_changed_by, record.status_changed_at, record.note) == (
        manual.status,
        manual.status_changed_by,
        manual.status_changed_at,
        manual.note,
    )
    assert storage.get_ospf_incident(incident_id).technical_recovered_at == (
        BASE_TIME + timedelta(seconds=15)
    )
    history = storage.get_alert_history(incident_id)
    assert len(history) == 2 and history[-1].source == "operator"


def test_backdated_observation_reconciles_membership_and_only_reopens_automatic_resolution(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    first = observe("r1-down", 10)
    incident_id = first.incidents[0].incident_id
    storage.apply_ospf_snapshot(first)
    storage.acknowledge(incident_id, "NOC", "keep")
    storage.apply_ospf_snapshot(observe("r1-full", 20))
    split = observe("r1-down", 30)
    storage.apply_ospf_snapshot(split)
    retired_id = split.incidents[1].incident_id
    moved_event = split.incidents[1].event_ids[0]

    assert storage.apply_ospf_snapshot(observe("r2-down", 15))
    record = storage.get_alert(incident_id)
    assert record.status is AlertLifecycleStatus.ACKNOWLEDGED
    assert (record.acknowledged_by, record.note) == ("NOC", "keep")
    assert storage.get_alert_history(incident_id)[-1].source == "ospf_reassessment"
    active = storage.get_ospf_incident(incident_id)
    retired = storage.get_ospf_incident(retired_id)
    assert active.technical_recovered_at is None
    assert retired.superseded_at is not None
    assert retired.event_refs[0].event_id == moved_event and not retired.event_refs[0].is_current
    assert any(ref.event_id == moved_event and ref.is_current for ref in active.event_refs)
    assert storage.get_alert(retired_id) is not None
    page = storage.query_alerts(
        AlertQuery(start=BASE_TIME, end=BASE_TIME + timedelta(minutes=1), page=1, page_size=10)
    )
    assert [alert.aggregate_id for alert in page.items] == [incident_id]
    claimed = storage.claim_notifications(EventSeverity.LOW, datetime.now(UTC))
    assert not claimed
    ospf_claim = storage.claim_ospf_notification((1234,), EventSeverity.LOW, datetime.now(UTC))
    assert ospf_claim is not None and ospf_claim.aggregate_id == incident_id


def test_snapshot_rolls_back_alert_history_evidence_and_revision_on_conflict(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    first = observe("r1-down", 1)
    storage.apply_ospf_snapshot(first)
    original_id = first.incidents[0].incident_id
    old_evidence = storage.get_ospf_incident(original_id)
    old_history = storage.get_alert_history(original_id)
    observe("r1-full", 3)
    valid = observe("r1-down", 4)
    first_incident, second_incident = valid.incidents
    invalid_incident = second_incident.model_copy(update={"evidence": first_incident.evidence})
    invalid = valid.model_copy(update={"incidents": (first_incident, invalid_incident)})
    with pytest.raises(StorageError, match="PostgreSQL operation failed"):
        storage.apply_ospf_snapshot(invalid)
    assert storage.get_alert(second_incident.incident_id) is None
    assert storage.get_alert_history(original_id) == old_history
    assert storage.get_ospf_incident(original_id) == old_evidence
    assert storage.get_alert(original_id).status is AlertLifecycleStatus.NEW
    with psycopg.connect(storage.dsn) as connection:
        assert connection.execute(
            "SELECT kind FROM ospf_notification_events ORDER BY notification_id"
        ).fetchall() == [("down",)]
    assert storage.apply_ospf_snapshot(valid)
    assert storage.get_alert(original_id).status is AlertLifecycleStatus.RESOLVED
    assert storage.get_alert(second_incident.incident_id).status is AlertLifecycleStatus.NEW


def test_concurrent_snapshots_converge_on_the_newest_revision(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    opened = observe("r1-down", 1)
    recovered = observe("r1-full", 2)
    incident_id = opened.incidents[0].incident_id
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(storage.apply_ospf_snapshot, snapshot)
            for snapshot in (recovered, opened)
        ]
        assert futures[0].result()
        futures[1].result()
    assert not storage.apply_ospf_snapshot(opened)
    assert storage.get_alert(incident_id).status is AlertLifecycleStatus.RESOLVED
    assert len(storage.get_alert_history(incident_id)) == 2


def test_migration_preserves_existing_alert_reference_and_notification(
    isolated_dsn: str, tmp_path: Path
) -> None:
    old_migrations = tmp_path / "pre_phase_3"
    old_migrations.mkdir()
    for migration in sorted(MIGRATIONS.glob("00[12]*.sql")):
        shutil.copyfile(migration, old_migrations / migration.name)
    old = PostgresAlertStorage(isolated_dsn, old_migrations)
    old.migrate()
    raw = (FIXTURES / "cisco-ios.log").read_text(encoding="utf-8").splitlines()[2]
    event = parse_syslog(raw, received_at=BASE_TIME, source_host="legacy").event
    assert event is not None
    rules = Path("config/correlation_rules.yaml")
    aggregate = CorrelationEngine.from_files(tmp_path / "legacy.db", rules).process(event).alert
    assert aggregate is not None
    with psycopg.connect(isolated_dsn) as connection:
        connection.execute(
            """
            INSERT INTO aggregated_alerts(
                aggregate_id, schema_version, rule_id, event_family, group_key, event_types,
                window_start, window_end, event_count, first_seen, last_seen, severity,
                status, acknowledged_by, acknowledged_at, status_changed_by, status_changed_at,
                note, notification_cooldown_seconds, created_at, updated_at
            ) VALUES (
                %s, '1.0', 'interface-link-state', 'link_state', '{}', '["link_down"]',
                %s, %s, 1, %s, %s, 'high', 'acknowledged', 'legacy', %s, 'legacy', %s,
                'keep', 300, %s, %s
            )
            """,
            (
                aggregate.aggregate_id,
                aggregate.window_start,
                aggregate.window_end,
                *((event.timestamp,) * 6),
            ),
        )
        connection.execute(
            """
            INSERT INTO alert_event_refs(event_id, aggregate_id, event_timestamp)
            VALUES (%s, %s, %s)
            """,
            (event.event_id, aggregate.aggregate_id, event.timestamp),
        )
    old.save_telegram_message_id(aggregate.aggregate_id, 1234, 42)
    before = old.get_alert(aggregate.aggregate_id)
    current = PostgresAlertStorage(isolated_dsn, MIGRATIONS)
    current.migrate()
    current.migrate()

    assert current.get_alert(aggregate.aggregate_id) == before
    assert current.get_telegram_message_id(aggregate.aggregate_id, 1234) == 42
    (baseline,) = current.get_alert_history(aggregate.aggregate_id)
    assert (baseline.source, baseline.previous_status, baseline.note) == ("baseline", None, "keep")
    with psycopg.connect(isolated_dsn) as connection:
        assert connection.execute(
            "SELECT event_id FROM alert_event_refs WHERE aggregate_id = %s",
            (aggregate.aggregate_id,),
        ).fetchone() == (event.event_id,)
    legacy = current.get_alert_evidence(aggregate.aggregate_id)
    assert legacy is not None
    assert legacy.event_refs[0].source_ip is None and legacy.event_refs[0].event_type is None
    current.upsert_alert(
        aggregate, NormalizedEvent.model_validate(event.model_dump() | {"source_ip": "192.0.2.88"})
    )
    backfilled = current.get_alert_evidence(aggregate.aggregate_id)
    assert backfilled is not None and backfilled.event_refs[0].source_ip == "192.0.2.88"


def test_authenticated_operational_routes_use_postgres_for_filters_csv_and_lifecycle(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
    tmp_path: Path,
) -> None:
    seconds_before_now = int((datetime.now(UTC) - BASE_TIME).total_seconds()) - 60
    snapshot = observe("r1-down", seconds_before_now)
    incident_id = snapshot.incidents[0].incident_id
    storage.apply_ospf_snapshot(snapshot)
    rules = Path("config/correlation_rules.yaml")
    engine = CorrelationEngine.from_files(tmp_path / "link.db", rules)
    raw = (FIXTURES / "cisco-ios.log").read_text(encoding="utf-8").splitlines()[2]
    parsed = parse_syslog(raw, received_at=BASE_TIME, source_host="switch%_literal").event
    assert parsed is not None
    event = NormalizedEvent.model_validate(
        parsed.model_dump()
        | {
            "source_ip": "192.0.2.88",
            "timestamp": datetime.now(UTC) - timedelta(seconds=30),
            "received_at": datetime.now(UTC),
        }
    )
    aggregate = engine.process(event).alert
    assert aggregate is not None
    storage.upsert_alert(aggregate, event)

    app = create_app(
        Settings(
            database_path=tmp_path / "web.db",
            dashboard_backend="operational",
            session_secret="networksec-integration-test-secret-value",
            admin_username="test-operator",
            admin_password_hash=hash_password("test-password", iterations=10000),
        ),
        log_storage=LokiLogStorage("http://127.0.0.1:1"),
        alert_storage=storage,
    )
    with TestClient(app, follow_redirects=False) as client:
        login = client.get("/login").text
        token = login.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        assert (
            client.post(
                "/login",
                data={"username": "test-operator", "password": "test-password", "csrf": token},
            ).status_code
            == 303
        )
        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
        csrf = dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        match = {"rule_id": "interface-link-state", "source_ip": "192.0.2.88", "search": "%_"}
        alert_page = client.get("/alerts", params=match)
        assert alert_page.status_code == 200 and aggregate.aggregate_id in alert_page.text
        assert incident_id not in alert_page.text
        csv_rows = list(
            csv.DictReader(io.StringIO(client.get("/alerts/export.csv", params=match).text))
        )
        assert len(csv_rows) == 1 and csv_rows[0]["source_ip"] == "192.0.2.88"
        assert client.get("/api/v1/alerts", params={"source_ip": "192.0.2.1"}).json()["total"] == 0
        literal = client.get("/api/v1/alerts", params={"search": "%_"}).json()
        assert [item["aggregate_id"] for item in literal["items"]] == [aggregate.aggregate_id]
        first = client.get("/api/v1/alerts", params={"page_size": 1}).json()
        second = client.get("/api/v1/alerts", params={"page_size": 1, "page": 2}).json()
        assert first["total"] == second["total"] == 2
        assert {first["items"][0]["aggregate_id"], second["items"][0]["aggregate_id"]} == {
            aggregate.aggregate_id,
            incident_id,
        }
        neighbor_page = client.get("/api/v1/alerts", params={"device_name": "192.0.2.2"})
        assert neighbor_page.json()["items"][0]["aggregate_id"] == incident_id

        path = f"/alerts/{incident_id}"
        assert "Awaiting confirmed Full" in client.get(path).text
        assert client.post(path + "/resolve", data={"csrf": "wrong"}).status_code == 403
        assert (
            client.post(path + "/ack", data={"csrf": csrf, "note": "Acknowledged"}).status_code
            == 303
        )
        assert (
            client.post(
                path + "/resolve", data={"csrf": csrf, "note": "Cable replaced"}
            ).status_code
            == 303
        )
        api_path = f"/api/v1{path}"
        resolved = client.get(api_path).json()
        evidence_url = api_path + "/evidence"
        evidence = client.get(evidence_url).json()
        late_note = {"note": "Late page"}
        assert client.post(api_path + "/acknowledge", json=late_note).status_code == 403
        headers = {"X-CSRF-Token": csrf}
        late_ack = client.post(api_path + "/acknowledge", headers=headers, json=late_note)
        late_patch_ack = client.patch(
            api_path + "/status", headers=headers, json={"status": "acknowledged", **late_note}
        )
        assert late_ack.status_code == late_patch_ack.status_code == 200
        assert late_ack.json() == late_patch_ack.json() == resolved
        assert resolved["status"] == "resolved" and resolved["note"] == "Cable replaced"
        late_form = client.post(path + "/ack", data={"csrf": csrf, **late_note})
        assert late_form.status_code == 303 and late_form.headers["location"] == path
        assert client.get(evidence_url).json() == evidence
        finished = client.get(path)
        assert "Cable replaced" in finished.text and "Awaiting confirmed Full" in finished.text
        assert evidence["ospf"]["adjacency"]["area"] == "0.0.0.0"
        assert [entry["status"] for entry in evidence["history"]] == [
            "new",
            "acknowledged",
            "resolved",
        ]
        assert evidence["event_refs"][0]["event_id"] == snapshot.incidents[0].event_ids[0]


class FakeOspfGateway:
    def __init__(self) -> None:
        self.sends: list[tuple[int, str, dict[str, Any] | None]] = []
        self.edits: list[tuple[int, int, str]] = []
        self.send_error: Exception | None = None
        self.edit_error: Exception | None = None

    async def send_message_once(
        self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> int:
        self.sends.append((chat_id, text, reply_markup))
        if self.send_error is not None:
            raise self.send_error
        return chat_id + 1000

    async def edit_message(
        self, chat_id: int, message_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> None:
        self.edits.append((chat_id, message_id, text))
        if self.edit_error is not None:
            raise self.edit_error


@pytest.mark.asyncio
async def test_ospf_telegram_lifecycle_uses_one_card_per_chat_and_confirmed_recovery(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    settings = Settings(
        allowed_chat_ids={10, 20},
        minimum_severity="medium",
        app_url="https://dashboard.example.com/lab",
    )
    gateway = FakeOspfGateway()
    now = datetime.now(UTC)
    opened = observe("r1-down", 1)
    incident_id = opened.incidents[0].incident_id
    storage.apply_ospf_snapshot(opened)
    assert not storage.apply_ospf_snapshot(opened)
    storage.apply_ospf_snapshot(observe("r2-down", 2))
    assert storage.claim_ospf_notification((10, 20), EventSeverity.HIGH, now) is None
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 2
    assert [chat for chat, _, _ in gateway.sends] == [10, 20]
    assert "OSPF Neighbor Down" in gateway.sends[0][1]
    assert "0.0.0.0" in gateway.sends[0][1] and "192.0.2.2" in gateway.sends[0][1]
    markup = gateway.sends[0][2]
    assert markup is not None
    assert markup["inline_keyboard"][0][0]["url"].endswith(f"/lab/alerts/{incident_id}")

    storage.apply_ospf_snapshot(observe("r1-full", 3))
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 0
    storage.acknowledge(incident_id, "<NOC>", "note kept in dashboard")
    storage.update_status(incident_id, "resolved", "Operator", None)
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 4
    assert "&lt;NOC&gt;" in gateway.edits[0][2]
    assert "resolved by operator" in gateway.edits[-1][2]
    assert "Neighbor Recovered" not in gateway.edits[-1][2]

    recovered = observe("r2-full", 4)
    assert storage.apply_ospf_snapshot(recovered)
    assert not storage.apply_ospf_snapshot(recovered)
    assert storage.apply_ospf_snapshot(observe("r2-full", 5))
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 2
    assert len(gateway.sends) == 2
    assert [(chat, message) for chat, message, _ in gateway.edits[-2:]] == [(10, 1010), (20, 1020)]
    assert all("OSPF Neighbor Recovered" in text for _, _, text in gateway.edits[-2:])
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 0


@pytest.mark.asyncio
async def test_ospf_telegram_reschedules_only_known_first_send_rejection_and_retries_edit(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    settings = Settings(
        allowed_chat_ids={10}, minimum_severity="medium", app_url="http://localhost:8000"
    )
    gateway = FakeOspfGateway()
    now = datetime.now(UTC)
    storage.apply_ospf_snapshot(observe("r1-down", 1))
    gateway.send_error = TelegramSendDeferred(5)
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 1
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 0
    gateway.send_error = None
    assert (
        await OspfNotificationWorker(settings, storage, gateway).run_once(
            now + timedelta(seconds=5)
        )
        == 1
    )
    assert len(gateway.sends) == 2 and gateway.sends[0][2] is None

    storage.apply_ospf_snapshot(observe("r1-full", 2))
    gateway.edit_error = ConnectionError("ambiguous edit")
    assert (
        await OspfNotificationWorker(settings, storage, gateway).run_once(
            now + timedelta(seconds=6)
        )
        == 1
    )
    assert (
        await OspfNotificationWorker(settings, storage, gateway).run_once(
            now + timedelta(seconds=20)
        )
        == 0
    )
    gateway.edit_error = None
    assert (
        await OspfNotificationWorker(settings, storage, gateway).run_once(
            now + timedelta(seconds=36)
        )
        == 1
    )
    assert len(gateway.sends) == 2 and gateway.edits[0] == gateway.edits[1]


@pytest.mark.asyncio
async def test_ospf_telegram_does_not_resend_after_ambiguous_first_send_or_process_loss(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(allowed_chat_ids={10, 20}, minimum_severity="medium")
    gateway = FakeOspfGateway()
    now = datetime.now(UTC)
    storage.apply_ospf_snapshot(observe("r1-down", 1))
    interrupted = storage.claim_ospf_notification((10,), EventSeverity.MEDIUM, now)
    assert interrupted is not None and interrupted.message_id is None
    # The process that claimed chat 10 may have posted successfully before losing its receipt.
    gateway.send_error = ConnectionError("sensitive-looking response body")
    assert await OspfNotificationWorker(settings, storage, gateway).run_once(now) == 1
    assert [call[0] for call in gateway.sends] == [20]
    assert "sensitive-looking" not in caplog.text
    storage.apply_ospf_snapshot(observe("r1-full", 2))
    assert (
        await OspfNotificationWorker(settings, storage, gateway).run_once(
            now + timedelta(minutes=15)
        )
        == 0
    )
    assert len(gateway.sends) == 1 and not gateway.edits


def test_ospf_reclaims_expired_edit_with_same_transition_and_fences_late_results(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    now = datetime.now(UTC)
    storage.apply_ospf_snapshot(observe("r1-down", 1))
    opened = storage.claim_ospf_notification((10,), EventSeverity.MEDIUM, now)
    assert opened is not None
    storage.finish_ospf_notification(opened, "delivered", now, 123)
    storage.apply_ospf_snapshot(observe("r1-full", 2))
    edit = storage.claim_ospf_notification((10,), EventSeverity.HIGH, now)
    assert edit is not None and edit.kind is OspfNotificationKind.RECOVERED
    assert edit.message_id == 123

    future = now + timedelta(minutes=11)
    reclaimed = storage.claim_ospf_notification((10,), EventSeverity.HIGH, future)
    assert reclaimed is not None and reclaimed.notification_id == edit.notification_id
    assert reclaimed.claim_token != edit.claim_token
    storage.finish_ospf_notification(edit, "skipped", future)
    assert storage.claim_ospf_notification((10,), EventSeverity.HIGH, future) is None
    storage.finish_ospf_notification(reclaimed, "delivered", future)
    with psycopg.connect(storage.dsn) as connection:
        assert connection.execute(
            "SELECT state FROM ospf_telegram_deliveries WHERE notification_id = %s",
            (edit.notification_id,),
        ).fetchone() == ("delivered",)


def test_ospf_claim_is_exclusive_and_queued_stale_recovery_is_withdrawn(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
) -> None:
    now = datetime.now(UTC)
    storage.apply_ospf_snapshot(observe("r1-down", 1))
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: storage.claim_ospf_notification((10,), EventSeverity.MEDIUM, now),
                range(2),
            )
        )
    (opened,) = (claim for claim in results if claim is not None)
    assert opened.kind is OspfNotificationKind.DOWN
    storage.finish_ospf_notification(opened, "delivered", now, 123)
    storage.apply_ospf_snapshot(observe("r1-full", 10))
    storage.apply_ospf_snapshot(observe("r2-down", 5))
    retracted = storage.claim_ospf_notification((10,), EventSeverity.MEDIUM, now)
    assert retracted is not None and retracted.kind is OspfNotificationKind.RECOVERY_RETRACTED
    storage.finish_ospf_notification(retracted, "delivered", now)
    storage.apply_ospf_snapshot(observe("r2-full", 11))
    confirmed = storage.claim_ospf_notification((10,), EventSeverity.MEDIUM, now)
    assert confirmed is not None and confirmed.kind is OspfNotificationKind.RECOVERED
    assert confirmed.occurred_at == BASE_TIME + timedelta(seconds=11)


def test_ospf_notification_migration_reuses_existing_card(
    isolated_dsn: str,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
    tmp_path: Path,
) -> None:
    before = tmp_path / "migrations"
    before.mkdir()
    for migration in MIGRATIONS.glob("00[1-4]*.sql"):
        shutil.copyfile(migration, before / migration.name)
    old = PostgresAlertStorage(isolated_dsn, before)
    old.migrate()
    opened = observe("r1-down", 1)
    incident_id = opened.incidents[0].incident_id
    old.apply_ospf_snapshot(opened)
    old.save_telegram_message_id(incident_id, 10, 123)
    with psycopg.connect(isolated_dsn) as connection:
        connection.execute(
            "UPDATE aggregated_alerts SET notification_count = 1 WHERE aggregate_id = %s",
            (incident_id,),
        )

    storage = PostgresAlertStorage(isolated_dsn, MIGRATIONS)
    storage.migrate()
    storage.migrate()
    claim = storage.claim_ospf_notification((10,), EventSeverity.HIGH, datetime.now(UTC))
    assert claim is not None and claim.kind is OspfNotificationKind.DOWN
    assert claim.aggregate_id == incident_id and claim.message_id == 123
    assert storage.claim_ospf_notification((20,), EventSeverity.MEDIUM, datetime.now(UTC)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("dual_routeros", [False, True], ids=["mixed-vendor", "dual-routeros"])
async def test_ospf_spool_to_loki_incident_dashboard_and_telegram(
    storage: PostgresAlertStorage,
    isolated_dsn: str,
    ospf_rules_path: Path,
    tmp_path: Path,
    dual_routeros: bool,
) -> None:
    loki_url = os.getenv("NETWORKSEC_TEST_LOKI_URL")
    if not loki_url:
        pytest.skip("requires a disposable Loki and NETWORKSEC_TEST_LOKI_URL")

    run_id = uuid4().hex[:12]
    devices = {side: f"{side}-{run_id}" for side in ("R1", "R2")}
    rules = yaml.safe_load(ospf_rules_path.read_text(encoding="utf-8"))
    for endpoint in rules["ospf"]["links"][0]["endpoints"]:
        side = endpoint["device_name"]
        if dual_routeros and side == "R2":
            endpoint["interface_name"] = "ether4"
        endpoint["device_name"] = devices[side]
        endpoint["source_addresses"] = ["198.51.100.1" if side == "R1" else "198.51.100.2"]
    ospf_rules_path.write_text(yaml.safe_dump(rules), encoding="utf-8")

    r1_down_sample, r1_full_sample, intermediate_sample = MIKROTIK[:3]
    r2_down_sample, r2_full_sample = CISCO[:2]
    if dual_routeros:
        (
            r1_down_sample,
            r2_down_sample,
            intermediate_sample,
            _,
            r1_full_sample,
            r2_full_sample,
        ) = MIKROTIK_DUAL

    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=2)
    spool = tmp_path / "processor.jsonl"
    processor_db = tmp_path / "processor.db"
    journal = tmp_path / "correlation.db"
    loki = LokiLogStorage(loki_url)
    catalog = PostgresBackendStorage(isolated_dsn, MIGRATIONS)
    storage_writer = StorageWriter(loki, storage)
    settings = Settings(
        database_path=tmp_path / "web.db",
        dashboard_backend="operational",
        session_secret="networksec-integration-test-secret-value",
        admin_username="test-operator",
        admin_password_hash=hash_password("test-password", iterations=10000),
        allowed_chat_ids={10},
        minimum_severity="medium",
        app_url="https://dashboard.example.com",
        postgres_dsn=isolated_dsn,
        correlation_rules_path=ospf_rules_path,
    )
    app = create_app(settings, log_storage=loki, alert_storage=storage)
    gateway = FakeOspfGateway()

    def worker() -> ProcessingWorker:
        state = ProcessorStateStore(processor_db)
        state.initialize()
        return ProcessingWorker(
            spool_path=spool,
            state=state,
            correlation=CorrelationEngine.from_files(journal, ospf_rules_path),
            logs=loki,
            writer=storage_writer,
            catalog=catalog,
            source_timezone=UTC,
        )

    def envelope(side: str, sample: str, second: int, *, received_second: int = 30) -> str:
        timestamp = base + timedelta(seconds=second)
        host = devices[side]
        if side == "R1" or dual_routeros:
            body = sample[sample.index("edge-v2") :]
            message = f"{timestamp.isoformat()} {host} route,ospf,info {body}"
            pri = 134
        else:
            body = sample[sample.index("%OSPF-") :]
            message = f"{timestamp.strftime('%b %d %H:%M:%S')}.001: {body}"
            pri = 189
        source_ip = "198.51.100.1" if side == "R1" else "198.51.100.2"
        # Match the fields emitted by NetworkSecProcessorEnvelope in rsyslog.
        return json.dumps(
            {
                "schema_version": "1.0",
                "received_at": (base + timedelta(seconds=received_second)).isoformat(),
                "source_host": host,
                "source_ip": source_ip,
                "raw_message": f"<{pri}>{message}",
                "parse_message": message,
            }
        )

    async def ingest(consumer: ProcessingWorker, *records: str) -> None:
        with spool.open("a", encoding="utf-8", newline="\n") as output:
            output.write("\n".join(records) + "\n")
        for _ in records:
            assert await consumer.process_once()
        assert not await consumer.process_once()

    r1_down = envelope("R1", r1_down_sample, 1)
    r1_down_replay = envelope("R1", r1_down_sample, 1, received_second=31)
    r2_down = envelope("R2", r2_down_sample, 2)
    consumer = worker()
    await ingest(consumer, r1_down, r2_down, r1_down_replay)
    queue = storage.query_alerts(
        AlertQuery(start=base, end=datetime.now(UTC), page=1, page_size=25)
    )
    assert queue.total == 1 and queue.items[0].count == 2
    incident_id = queue.items[0].aggregate_id
    assert await OspfNotificationWorker(settings, storage, gateway).run_once() == 1
    assert "OSPF Neighbor Down" in gateway.sends[0][1]
    assert gateway.sends[0][2] == {
        "inline_keyboard": [
            [
                {
                    "text": "Open dashboard",
                    "url": f"https://dashboard.example.com/alerts/{incident_id}",
                }
            ]
        ]
    }

    with TestClient(app, follow_redirects=False) as client:

        def page_event_ids(side: str, *expected: str) -> set[str]:
            params = {
                "start": base.isoformat(),
                "end": (base + timedelta(seconds=10)).isoformat(),
                "device_name": devices[side],
                "include_ospf": "true",
                "page_size": "1",
            }
            tokens: set[str] = set()
            event_ids: set[str] = set()
            for index, event_type in enumerate(expected):
                response = client.get("/api/v1/events", params=params)
                assert response.status_code == 200
                page = response.json()
                assert page["schema_version"] == "1.0" and page["page_size"] == 1
                assert len(page["items"]) == 1
                event = page["items"][0]
                assert event["schema_version"] == "1.1" and event["event_type"] == event_type
                assert event["vendor"] == ("mikrotik" if side == "R1" or dual_routeros else "cisco")
                assert event["event_id"] not in event_ids
                event_ids.add(event["event_id"])
                cursor = page["next_cursor"]
                if index + 1 < len(expected):
                    assert cursor and cursor not in tokens
                    tokens.add(cursor)
                    params["cursor"] = cursor
                else:
                    assert cursor is None
            return event_ids

        detail_path = f"/alerts/{incident_id}"
        alert_api_path = f"/api/v1{detail_path}"
        evidence_path = alert_api_path + "/evidence"
        assert client.get(evidence_path).status_code == 401
        login = client.get("/login").text
        csrf = login.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        assert (
            client.post(
                "/login",
                data={"username": "test-operator", "password": "test-password", "csrf": csrf},
            ).status_code
            == 303
        )
        assert client.get("/api/v1/storage/health").json()["status"] == "ok"
        down_topology = client.get("/api/v1/topology")
        assert down_topology.status_code == 200, down_topology.text
        (down_link,) = down_topology.json()["links"]
        assert down_link["status"] == "down"
        assert down_link["related_incident_ids"] == [incident_id]
        down_ids = page_event_ids("R1", "routing_neighbor_down") | page_event_ids(
            "R2", "routing_neighbor_down"
        )
        opened = client.get(evidence_path).json()
        assert {ref["event_id"] for ref in opened["event_refs"]} == down_ids
        assert {ref["reporter_router_id"] for ref in opened["event_refs"]} == {
            "192.0.2.1",
            "192.0.2.2",
        }
        detail = client.get(detail_path)
        assert "Awaiting confirmed Full" in detail.text
        csrf = detail.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        assert (
            client.post(
                detail_path + "/ack", data={"csrf": csrf, "note": "Investigating transit"}
            ).status_code
            == 303
        )

        # Restart between Down and Full, then deliver an older R2 Full out of order.
        consumer = worker()
        await ingest(
            consumer,
            envelope("R1", intermediate_sample, 3),
            envelope("R1", r1_full_sample, 4),
            envelope("R2", r2_full_sample, 0),
        )
        pending = client.get(evidence_path).json()
        assert pending["ospf"]["technical_recovered_at"] is None
        assert [row["status"] for row in pending["history"]] == ["new", "acknowledged"]
        r1_pending_ids = page_event_ids(
            "R1", "routing_neighbor_up", "routing_neighbor_state_change", "routing_neighbor_down"
        )
        r2_pending_ids = page_event_ids("R2", "routing_neighbor_down", "routing_neighbor_up")
        assert down_ids <= r1_pending_ids | r2_pending_ids
        await OspfNotificationWorker(settings, storage, gateway).run_once()
        assert all("OSPF Neighbor Recovered" not in edit[2] for edit in gateway.edits)

        r2_full = envelope("R2", r2_full_sample, 5)
        r2_full_replay = envelope("R2", r2_full_sample, 5, received_second=31)
        await ingest(consumer, r2_full, r2_full_replay, r2_down)
        health = consumer.state.health()
        assert health is not None and (health.processed_count, health.dead_letter_count) == (9, 0)
        evidence = client.get(evidence_path).json()
        assert evidence["ospf"]["technical_recovered_at"] is not None
        assert [(row["status"], row["source"]) for row in evidence["history"]] == [
            ("new", "system"),
            ("acknowledged", "operator"),
            ("resolved", "ospf_recovery"),
        ]
        detail = client.get(detail_path).text
        assert "Investigating transit" in detail and "test-operator" in detail

        resolved = client.get(alert_api_path).json()
        late_ack = client.post(
            alert_api_path + "/acknowledge",
            headers={"X-CSRF-Token": csrf},
            json={"note": "Delayed ACK from earlier page"},
        )
        assert late_ack.status_code == 200 and late_ack.json() == resolved
        assert resolved["status"] == "resolved" and resolved["note"] == "Investigating transit"
        assert client.get(evidence_path).json() == evidence

        observed_ids = page_event_ids(
            "R1", "routing_neighbor_up", "routing_neighbor_state_change", "routing_neighbor_down"
        ) | page_event_ids(
            "R2", "routing_neighbor_up", "routing_neighbor_down", "routing_neighbor_up"
        )
        assert len(observed_ids) == 6 and r1_pending_ids | r2_pending_ids < observed_ids
        (recovered_link,) = client.get("/api/v1/topology").json()["links"]
        assert recovered_link["id"] == down_link["id"] and recovered_link["status"] == "up"
        summary = client.get("/api/v1/dashboard/summary", params={"start": base.isoformat()})
        assert summary.status_code == 200, summary.text
        assert summary.json()["total_events"] == 6
        assert summary.json()["resolved_incidents"] == 1
        for event_id in down_ids:
            event_detail = client.get(f"/api/v1/events/{event_id}", params={"include_raw": True})
            assert event_detail.status_code == 200, event_detail.text
            assert event_detail.json()["related_incident_ids"] == [incident_id]
            assert event_detail.json()["event"]["collector_ip"] in {"198.51.100.1", "198.51.100.2"}
        for device in devices.values():
            params = {"start": base.isoformat(), "device_name": device}
            assert client.get("/api/v1/events", params=params).json()["items"] == []
        evidence_ids = {ref["event_id"] for ref in evidence["event_refs"]}
        assert evidence_ids and evidence_ids <= observed_ids

    assert await OspfNotificationWorker(settings, storage, gateway).run_once() == 1
    assert len(gateway.sends) == 1
    recoveries = [edit for edit in gateway.edits if "OSPF Neighbor Recovered" in edit[2]]
    assert len(recoveries) == 1 and recoveries[0][:2] == (10, 1010)
    assert await OspfNotificationWorker(settings, storage, gateway).run_once() == 0


@pytest.mark.parametrize("resolve_first", [False, True], ids=["ack-first", "resolve-first"])
def test_qa_postgres_concurrent_ack_resolve_history_remains_a_serial_chain(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
    isolated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
    resolve_first: bool,
) -> None:
    opened = observe("r1-down", 11)
    storage.apply_ospf_snapshot(opened)
    incident_id = opened.incidents[0].incident_id
    incident = storage.get_ospf_incident(incident_id)
    first_storage = PostgresAlertStorage(isolated_dsn, MIGRATIONS)
    follower_name = "qa05-" + uuid4().hex
    follower_dsn = make_conninfo(isolated_dsn, application_name=follower_name)
    second_storage = PostgresAlertStorage(follower_dsn, MIGRATIONS)

    def change(backend: PostgresAlertStorage, resolve: bool) -> AlertRecord | None:
        if resolve:
            return backend.update_status(incident_id, "resolved", "QA operator", "QA resolve")
        return backend.acknowledge(incident_id, "QA analyst", "QA ACK")

    with ThreadPoolExecutor(max_workers=1) as pool:
        # Hold the first real write open until PostgreSQL observes the second transaction wait.
        with psycopg.connect(isolated_dsn, row_factory=dict_row) as first:
            monkeypatch.setattr(first_storage, "_connect", lambda: nullcontext(first))
            leading = change(first_storage, resolve_first)
            assert leading is not None
            future = pool.submit(change, second_storage, not resolve_first)
            with psycopg.connect(isolated_dsn, autocommit=True) as observer:
                deadline = monotonic() + 5
                while not future.done() and monotonic() < deadline:
                    blocked = observer.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM pg_stat_activity
                            WHERE application_name = %s AND %s = ANY(pg_blocking_pids(pid))
                        )
                        """,
                        (follower_name, first.info.backend_pid),
                    ).fetchone()
                    if blocked == (True,):
                        break
                    sleep(0.01)
                else:
                    pytest.fail(
                        "PostgreSQL did not observe the second request waiting on the first"
                    )
        trailing = future.result(timeout=10)

    assert trailing is not None and trailing.status is AlertLifecycleStatus.RESOLVED
    history = storage.get_alert_history(incident_id)
    expected = [(None, "new", None, None)]
    if not resolve_first:
        expected.append(("new", "acknowledged", "QA analyst", "QA ACK"))
    expected.append(
        ("new" if resolve_first else "acknowledged", "resolved", "QA operator", "QA resolve")
    )
    assert [(row.previous_status, row.status, row.actor, row.note) for row in history] == expected
    record = storage.get_alert(incident_id)
    assert record == trailing
    assert record.acknowledged_by == (None if resolve_first else "QA analyst")
    assert record.status_changed_by == "QA operator" and record.note == "QA resolve"
    assert storage.get_ospf_incident(incident_id) == incident


def test_qa_postgres_search_treats_quotes_and_wildcards_as_literal(
    storage: PostgresAlertStorage, observe: Callable[[str, int], OspfCorrelationSnapshot]
) -> None:
    opened = observe("r1-down", 11)
    storage.apply_ospf_snapshot(opened)
    incident_id = opened.incidents[0].incident_id
    assert storage.acknowledge(incident_id, "QA analyst", "O'Brien lab 100%_done") is not None
    for search, total in (("O'Brien", 1), ("100%_", 1), ("100_%", 0)):
        query = AlertQuery(
            start=BASE_TIME,
            end=BASE_TIME + timedelta(minutes=1),
            page=1,
            page_size=10,
            search=search,
        )
        assert storage.query_alerts(query).total == total


def test_qa_postgres_stale_ack_preserves_resolved_incident(
    storage: PostgresAlertStorage, observe: Callable[[str, int], OspfCorrelationSnapshot]
) -> None:
    opened = observe("r1-down", 11)
    storage.apply_ospf_snapshot(opened)
    incident_id = opened.incidents[0].incident_id
    resolved = storage.update_status(incident_id, "resolved", "QA operator", "QA resolve")
    assert resolved is not None and resolved.status is AlertLifecycleStatus.RESOLVED
    before_ack = storage.get_alert_evidence(incident_id)
    assert before_ack is not None
    assert storage.acknowledge(incident_id, "QA stale page", "late acknowledgement") == resolved
    record = storage.get_alert(incident_id)
    assert record is not None and record.status is AlertLifecycleStatus.RESOLVED
    assert storage.get_alert_evidence(incident_id) == before_ack


def test_qa05_repeated_operator_updates_preserve_transition_metadata(
    storage: PostgresAlertStorage, observe: Callable[[str, int], OspfCorrelationSnapshot]
) -> None:
    opened = observe("r1-down", 11)
    assert storage.apply_ospf_snapshot(opened)
    incident_id = opened.incidents[0].incident_id
    ack = storage.acknowledge(incident_id, "analyst", "initial ACK")
    assert ack is not None
    assert storage.acknowledge(incident_id, "retry", "initial ACK") == ack
    revised = storage.acknowledge(incident_id, "editor", "updated investigation note")
    assert revised is not None and revised.note == "updated investigation note"
    assert (revised.acknowledged_by, revised.acknowledged_at) == (
        ack.acknowledged_by,
        ack.acknowledged_at,
    )
    assert revised.status_changed_by == ack.status_changed_by == "analyst"
    resolved = storage.update_status(incident_id, "resolved", "operator", None)
    assert resolved is not None and resolved.note == revised.note
    assert resolved.acknowledged_by == ack.acknowledged_by
    assert storage.update_status(incident_id, "resolved", "retry", None) == resolved
    assert storage.acknowledge(incident_id, "late", "ignored") == resolved
    assert not storage.apply_ospf_snapshot(opened)
    history = storage.get_alert_history(incident_id)
    assert [(row.status, row.actor, row.note) for row in history] == [
        ("new", None, None),
        ("acknowledged", "analyst", "initial ACK"),
        ("resolved", "operator", "updated investigation note"),
    ]
    reopened = storage.update_status(incident_id, "new", "operator", "reopened explicitly")
    assert reopened is not None and reopened.status is AlertLifecycleStatus.NEW
    reopened_ack = storage.acknowledge(incident_id, "analyst", None)
    assert reopened_ack is not None and reopened_ack.status is AlertLifecycleStatus.ACKNOWLEDGED


@pytest.mark.parametrize("status", ["acknowledged", "resolved"])
def test_qa05_operator_transition_rolls_back_if_outbox_write_fails(
    storage: PostgresAlertStorage,
    observe: Callable[[str, int], OspfCorrelationSnapshot],
    isolated_dsn: str,
    status: str,
) -> None:
    opened = observe("r1-down", 11)
    assert storage.apply_ospf_snapshot(opened)
    incident_id = opened.incidents[0].incident_id
    before = storage.get_alert_evidence(incident_id)
    assert before is not None
    with psycopg.connect(isolated_dsn) as connection:
        connection.execute(
            """
            ALTER TABLE ospf_notification_events ADD CONSTRAINT test_reject_operator_notification
            CHECK (kind NOT IN ('acknowledged', 'operator_resolved'))
            """
        )
    with pytest.raises(StorageError) as error:
        storage.update_status(incident_id, status, "operator", "should roll back")
    assert isinstance(error.value.__cause__, psycopg.errors.CheckViolation)
    with psycopg.connect(isolated_dsn) as connection:
        assert connection.execute(
            "SELECT kind FROM ospf_notification_events WHERE aggregate_id = %s", (incident_id,)
        ).fetchall() == [("down",)]
    assert storage.get_alert_evidence(incident_id) == before
