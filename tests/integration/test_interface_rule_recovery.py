"""Verified Cisco interface transitions and concurrent rule persistence on PostgreSQL."""

from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from app.parsers import parse_syslog
from app.schemas.api import AlertLifecycleStatus
from app.schemas.event import EventType, NormalizedEvent
from app.services.backend import EventFilters
from app.services.correlation import CorrelationEngine
from app.services.managed_rules import RuleCreate, RulePatch
from app.storage.backend import PostgresBackendStorage
from app.storage.managed_rules import RuleConflict

pytestmark = pytest.mark.storage_integration

_BASE = datetime(2026, 10, 26, 12, tzinfo=UTC)
_CISCO = Path("fixtures/logs/cisco-ios.log")
_SOURCE = "192.0.2.30"


@pytest.fixture
def backend() -> Iterator[tuple[str, PostgresBackendStorage]]:
    dsn = os.getenv("NETWORKSEC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires NETWORKSEC_TEST_POSTGRES_DSN for a disposable PostgreSQL instance")
    name = f"interface_{uuid4().hex}"
    schema = sql.Identifier(name)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        try:
            isolated = make_conninfo(dsn, options=f"-c search_path={name}")
            storage = PostgresBackendStorage(isolated, Path("migrations/postgresql"))
            storage.migrate()
            yield isolated, storage
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(schema))


def _cisco(kind: str, second: int, *, source_host: str = "core-switch") -> NormalizedEvent:
    line = next(line for line in _CISCO.read_text(encoding="utf-8").splitlines() if kind in line)
    at = _BASE + timedelta(seconds=second)
    raw = at.strftime("%b %d %H:%M:%S") + ".000: " + line[line.index("%") :]
    event = parse_syslog(raw, received_at=at, source_host=source_host).event
    assert event is not None
    return event


def _interface(state: str, second: int) -> NormalizedEvent:
    event = _cisco("%LINK-3-UPDOWN", second)
    raw = event.raw_message.removesuffix("down") + state
    result = parse_syslog(raw, received_at=event.received_at, source_host=event.device_name)
    assert result.event is not None
    assert result.event.event_type.value == f"link_{state}"
    return result.event


def _publish(
    engine: CorrelationEngine,
    storage: PostgresBackendStorage,
    event: NormalizedEvent,
    source: str = _SOURCE,
) -> str:
    aggregate = engine.process(event).alert
    assert aggregate is not None
    storage.upsert_alert(aggregate, event)
    storage.record_event(event, source, 189, True, None)
    return aggregate.aggregate_id


def test_cross_window_up_uses_provenance_and_preserves_evidence(
    backend: tuple[str, PostgresBackendStorage], tmp_path: Path
) -> None:
    dsn, storage = backend
    engine = CorrelationEngine.from_files(
        tmp_path / "journal.db", Path("config/correlation_rules.yaml")
    )
    down = _interface("down", 10)
    identifier = _publish(engine, storage, down)
    _publish(engine, storage, _interface("up", 10))
    _publish(engine, storage, _interface("up", 15), "192.0.2.31")
    alert = storage.get_alert(identifier)
    assert alert is not None and alert.status is AlertLifecycleStatus.NEW
    storage.acknowledge(identifier, "analyst", "investigating")

    up = _interface("up", 65)
    up_only = _publish(engine, storage, up)
    assert up_only != identifier
    # A replay through a fresh storage adapter leaves all counts and history intact.
    restarted = PostgresBackendStorage(dsn, Path("migrations/postgresql"))
    restarted.migrate()
    assert _publish(engine, restarted, up) == up_only
    evidence = restarted.get_alert_evidence(identifier)
    assert evidence is not None and evidence.alert.status is AlertLifecycleStatus.RESOLVED
    assert [entry.source for entry in evidence.history] == [
        "system",
        "operator",
        "interface_recovery",
    ]
    assert len({ref.event_id for ref in evidence.event_refs}) == len(evidence.event_refs) == 4
    assert up.event_id in {ref.event_id for ref in evidence.event_refs}
    assert restarted.relations(up.event_id).incident_ids == [identifier]
    window = EventFilters(_BASE, _BASE + timedelta(minutes=5))
    assert [row.aggregate_id for row in restarted.incidents(window, 1, 20).items] == [identifier]
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT incident_id FROM kpi_incident_events WHERE event_id = %s",
            (up.event_id,),
        ).fetchall() == [(identifier,)]


def test_delayed_down_restores_ack_and_keeps_operator_resolution(
    backend: tuple[str, PostgresBackendStorage], tmp_path: Path
) -> None:
    _, storage = backend
    engine = CorrelationEngine.from_files(
        tmp_path / "journal.db", Path("config/correlation_rules.yaml")
    )
    first_down = _interface("down", 1)
    position = _publish(engine, storage, first_down)
    storage.acknowledge(position, "analyst", "retain prior ACK")
    _publish(engine, storage, _interface("up", 5))
    assert _publish(engine, storage, _interface("down", 6)) == position
    result = storage.get_alert(position)
    assert result is not None and result.status is AlertLifecycleStatus.ACKNOWLEDGED
    assert result.note == "retain prior ACK"
    assert storage.get_alert_history(position)[-1].source == "interface_reassessment"
    storage.update_status(position, "resolved", "analyst", "manual closure")
    _publish(engine, storage, _interface("up", 9))
    _publish(engine, storage, _interface("down", 12))
    evidence = storage.get_alert_evidence(position)
    assert evidence is not None and evidence.alert.status is AlertLifecycleStatus.RESOLVED
    assert evidence.alert.status_changed_by == "analyst"
    assert evidence.history[-1].source == "operator"


def test_managed_rule_concurrent_replay_and_prior_ack_reassessment(
    backend: tuple[str, PostgresBackendStorage], tmp_path: Path
) -> None:
    _, storage = backend
    engine = CorrelationEngine.from_files(
        tmp_path / "journal.db", Path("config/correlation_rules.yaml")
    )
    rule = RuleCreate.model_validate(
        {
            "id": "test-port-rule",
            "enabled": True,
            "definition": {
                "name": "Port security fixture",
                "priority": 1,
                "severity": "high",
                "category": "security",
                "event_types": ["port_security"],
                "recovery_types": ["configuration_change"],
                "group_by": ["device_name"],
                "threshold": 2,
                "window_seconds": 60,
            },
        }
    )
    storage.update_rule(rule, engine.config, rule.id, "admin")
    observations = [_cisco("%PORT_SECURITY-2", second) for second in range(1, 7)]

    def insert(event: NormalizedEvent) -> None:
        storage.record_event(event, _SOURCE, None, False, None, True)

    with ThreadPoolExecutor(max_workers=6) as workers:
        list(workers.map(insert, [*observations, *observations]))
    bounds = EventFilters(_BASE, _BASE + timedelta(minutes=1))
    (incident,) = storage.incidents(bounds, 1, 20).items
    assert incident.count == 6
    evidence = storage.get_alert_evidence(incident.aggregate_id)
    assert evidence is not None and len(evidence.event_refs) == 6
    storage.acknowledge(incident.aggregate_id, "analyst", "retain prior ACK")
    recovery = _cisco("%SYS-5-CONFIG_I", 8)
    assert recovery.event_type is EventType.CONFIGURATION_CHANGE
    insert(recovery)
    insert(_cisco("%PORT_SECURITY-2", 9))
    evidence = storage.get_alert_evidence(incident.aggregate_id)
    assert evidence is not None and evidence.alert.status is AlertLifecycleStatus.ACKNOWLEDGED
    assert [entry.source for entry in evidence.history[-2:]] == [
        "rule_recovery",
        "rule_reassessment",
    ]


def test_unverified_port_flap_rule_is_disabled_and_cannot_activate(
    backend: tuple[str, PostgresBackendStorage], tmp_path: Path
) -> None:
    _, storage = backend
    engine = CorrelationEngine.from_files(
        tmp_path / "journal.db", Path("config/correlation_rules.yaml")
    )
    rules = {rule.id: rule for rule in storage.rules()}
    candidate = rules["repeated-port-flap"]
    assert not candidate.enabled
    assert candidate.definition.activation_error(engine.config) == (
        "port_flap has no verified parser or data source"
    )
    with pytest.raises(RuleConflict, match="no verified parser"):
        storage.update_rule(RulePatch(enabled=True), engine.config, candidate.id, "admin")
    assert {rule.id for rule in storage.rules() if rule.enabled} == {
        "repeated-login-failures",
        "repeated-firewall-denies",
        "configuration-change",
    }
