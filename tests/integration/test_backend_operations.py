"""Exercise the operational API against isolated PostgreSQL and fixture ingestion."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from app.config import Settings
from app.main import create_app
from app.schemas.backend import Category
from app.schemas.correlation import OspfCorrelationConfig
from app.schemas.event import EventSeverity, EventType, NormalizedEvent
from app.services.backend import EventFilters
from app.services.correlation import CorrelationEngine
from app.services.topology import TopologyInventory, build_topology
from app.storage.backend import PostgresBackendStorage
from app.storage.base import EventPage, EventQuery, StorageError
from app.web.auth import hash_password

pytestmark = pytest.mark.storage_integration
BOOTSTRAP_HASH = hash_password("test bootstrap password", 10_000)


@pytest.fixture
def backend():
    dsn = os.getenv("NETWORKSEC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires NETWORKSEC_TEST_POSTGRES_DSN for a disposable PostgreSQL instance")
    name = f"operations_{uuid4().hex}"
    schema = sql.Identifier(name)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        try:
            isolated = make_conninfo(dsn, options=f"-c search_path={name}")
            storage = PostgresBackendStorage(isolated, Path("migrations/postgresql"))
            storage.migrate()
            storage.migrate()
            yield isolated, storage
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(schema))


class MemoryLogs:
    def __init__(self) -> None:
        self.events: dict[str, NormalizedEvent] = {}

    async def ready(self) -> bool:
        return True

    async def push_event(self, event: NormalizedEvent) -> None:
        self.events[event.event_id] = event

    async def query_events(self, query: EventQuery) -> EventPage:
        return EventPage(
            tuple(
                event
                for event in self.events.values()
                if query.start <= event.timestamp < query.end
                and (query.event_id is None or query.event_id == event.event_id)
            )[: query.limit],
            None,
        )


def _event(
    at: datetime, kind: EventType = EventType.LOGIN_FAILURE, message: str = "test"
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=at,
        received_at=at,
        vendor="mikrotik",
        product="routeros",
        event_type=kind,
        severity="high",
        device_name="R1",
        interface_name="ether2",
        message=message,
        raw_message=message,
        parser_name="fixture",
    )


def _client(tmp_path: Path, dsn: str, logs: MemoryLogs | None = None) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_path=tmp_path / "legacy.db",
                session_secret="test-only-session",
                admin_password_hash=BOOTSTRAP_HASH,
                postgres_dsn=dsn,
                frontend_origins=("https://dashboard.example.test",),
                grafana_public_url="https://metrics.example.test/grafana",
            ),
            log_storage=logs or MemoryLogs(),
        )
    )


def _login(client: TestClient, name: str = "admin", password: str = "test bootstrap password"):
    response = client.post("/api/v1/auth/login", json={"username": name, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_registry_events_reports_and_kpi_parity(tmp_path, backend):
    dsn, storage = backend
    logs = MemoryLogs()
    real_now = datetime.now(UTC).replace(microsecond=0)
    now = real_now - timedelta(seconds=int(real_now.timestamp()) % 300 + 30)
    with _client(tmp_path, dsn, logs) as client:
        admin = _login(client)
        source = "192.0.2.41"
        body = {
            "name": "R1",
            "hostname": "R1.example.test",
            "device_type": "router",
            "source_addresses": [source],
            "vendor": "mikrotik",
            "expected_interval_seconds": 600,
            "management_ip": "192.0.2.42",
        }
        created = client.post("/api/v1/devices", headers=admin, json=body)
        assert created.status_code == 201, created.text
        device = created.json()["device_id"]
        duplicate = client.post("/api/v1/devices", headers=admin, json={**body, "name": "R2"})
        assert duplicate.status_code == 409
        rejected = client.patch(f"/api/v1/devices/{device}", headers=admin, json={"name": None})
        assert rejected.status_code == 422
        updated = client.patch(f"/api/v1/devices/{device}", headers=admin, json={"location": "lab"})
        assert updated.status_code == 200, updated.text
        for second in range(5):
            event = _event(now - timedelta(seconds=10 - second), message=f"login failure {second}")
            storage.record_event(event, source, 38, True, None, True)
            storage.record_event(event, source, 38, True, None, True)
        unknown = _event(now - timedelta(seconds=2), message="unregistered message")
        storage.record_event(unknown, "192.0.2.99", None, False, None, True)
        last = _event(now - timedelta(seconds=1), message="=1+1 password=test-fixture")
        logs.events[last.event_id] = last
        storage.record_event(last, source, 38, True, None, True)
        excluded = _event(
            now - timedelta(seconds=1), kind=EventType.ACL_DENY, message="Other category"
        )
        storage.record_event(excluded, source, 38, True, None, True)

        params = {
            "start": (now - timedelta(minutes=1)).isoformat(),
            "end": now.isoformat(),
            "device_id": device,
            "severity": "high",
            "category": "authentication",
        }
        events = client.get(
            "/api/v1/events", headers=admin, params={**params, "sort": "asc", "page_size": 2}
        )
        assert events.status_code == 200, events.text
        assert events.json()["total"] == 6
        assert events.json()["items"][0]["message"] == "login failure 0"
        search = client.get(
            "/api/v1/events/catalog", headers=admin, params={**params, "search": "REDACTED"}
        )
        assert search.json()["total"] == 1
        reported = client.get("/api/v1/reports/events", headers=admin, params=params)
        assert reported.status_code == 200 and reported.json()["total"] == 6
        detail = client.get(f"/api/v1/events/{last.event_id}?include_raw=true", headers=admin)
        assert detail.status_code == 200, detail.text
        assert detail.json()["raw_message"] == "<38>=1+1 password=[REDACTED]"
        assert detail.json()["facility"] == 4
        assert detail.json()["event"]["collector_ip"] == source
        assert (
            client.get(f"/api/v1/events/{unknown.event_id}", headers=admin).json()["event"][
                "device_id"
            ]
            is None
        )
        assert client.get("/api/v1/events/" + "0" * 64, headers=admin).status_code == 404
        summary = client.get("/api/v1/dashboard/summary", headers=admin, params=params)
        assert summary.status_code == 200, summary.text
        assert summary.json()["total_events"] == 6
        assert summary.json()["device_status"] == {"active": 1}
        assert summary.json()["by_category"] == {"authentication": 6}
        grafana = client.get("/api/v1/grafana/link", headers=admin, params=params)
        assert grafana.status_code == 200
        assert grafana.json()["url"].startswith(
            "https://metrics.example.test/grafana/d/network-event-kpis?"
        )
        assert f"var-device_id={device}" in grafana.json()["url"]
        report = client.get("/api/v1/reports/summary", headers=admin, params=params)
        assert report.json() == summary.json()
        activity = client.get("/api/v1/reports/devices", headers=admin, params=params)
        assert activity.status_code == 200, activity.text
        assert activity.json()["items"][0]["event_count"] == 6
        csv = client.get(
            "/api/v1/reports/export",
            headers=admin,
            params={**params, "report": "events", "format": "csv", "limit": 1},
        )
        assert csv.status_code == 200 and csv.headers["X-Report-Truncated"] == "true"
        assert "'=1+1 password=[REDACTED]" in csv.text and "test-fixture" not in csv.text
        assert (
            client.get(f"/api/v1/devices/{device}/events", headers=admin, params=params).json()[
                "total"
            ]
            == 6
        )
        incidents = client.get(f"/api/v1/devices/{device}/incidents", headers=admin, params=params)
        assert incidents.status_code == 200 and incidents.json()["total"] == 1
        nodes = client.get("/api/v1/topology/nodes", headers=admin)
        links = client.get("/api/v1/topology/links", headers=admin)
        node = client.get(f"/api/v1/topology/nodes/{device}", headers=admin)
        assert nodes.status_code == links.status_code == node.status_code == 200
        assert node.json() in nodes.json() and links.json() == []
        assert client.delete(f"/api/v1/devices/{device}", headers=admin).status_code == 204
        assert client.get(f"/api/v1/devices/{device}", headers=admin).json()["status"] == "disabled"
        enabled_export = client.get(
            "/api/v1/reports/export",
            headers=admin,
            params={**params, "report": "devices", "enabled": True},
        )
        assert enabled_export.status_code == 200 and enabled_export.json()["total"] == 0
        disabled_export = client.get(
            "/api/v1/reports/export",
            headers=admin,
            params={**params, "report": "devices", "enabled": False},
        )
        assert disabled_export.status_code == 200 and disabled_export.json()["total"] == 1
        audit = client.get("/api/v1/audit-logs", headers=admin)
        assert audit.status_code == 200, audit.text
        assert {"device.create", "device.update", "device.deactivate", "report.generate"} <= {
            row["action"] for row in audit.json()["items"]
        }

    dashboard = json.loads(Path("infra/grafana/dashboards/network-event-kpis.json").read_text())
    start, end = now - timedelta(minutes=1), real_now + timedelta(minutes=1)
    filters = EventFilters(
        start,
        end,
        device_id=UUID(device),
        device_name="R1",
        severity=EventSeverity.HIGH,
        category=Category.AUTHENTICATION,
    )
    substitutions = {
        "__from": str(int(start.timestamp() * 1000)),
        "__to": str(int(end.timestamp() * 1000)),
        "device:sqlstring": "'R1'",
        "device_id:sqlstring": f"'{device}'",
        "severity:sqlstring": "'high'",
        "category:sqlstring": "'authentication'",
        "incident:sqlstring": "'__networksec_all__'",
    }
    expected = storage.summary(filters)
    with psycopg.connect(dsn) as connection:
        panels = {}
        for panel in dashboard["panels"]:
            raw_sql = panel["targets"][0]["rawSql"]
            query = re.sub(r"\$\{([^}]+)\}", lambda match: substitutions[match[1]], raw_sql)
            panels[panel["title"]] = connection.execute(query).fetchall()

        assert panels["Total events"] == [(expected["total_events"],)] == [(6,)]
        assert panels["Critical and high events"] == [(0, expected["by_severity"]["high"])]
        assert dict(panels["Event severity"]) == expected["by_severity"]
        assert dict(panels["Event categories"]) == expected["by_category"]
        assert panels["Event volume"] == [
            (point.timestamp, point.count) for point in expected["trend"]
        ]
        assert panels["Event ingestion"] == [
            (point.timestamp, point.count) for point in expected["ingestion_trend"]
        ]
        assert float(panels["Ingestions per second"][0][0]) == pytest.approx(
            expected["events_per_second"]
        )
        assert dict(panels["Device status"]) == expected["device_status"] == {"disabled": 1}
        assert panels["Incident totals and resolution"] == [
            (
                expected["active_incidents"],
                expected["resolved_incidents"],
                expected["critical_incidents"],
                expected["high_incidents"],
                expected["mean_resolution_seconds"],
            )
        ]
        assert expected["active_incidents"] == 1

        # The name filter alone also includes the event from the unregistered address.
        raw_sql = dashboard["panels"][0]["targets"][0]["rawSql"]
        substitutions["device_id:sqlstring"] = "'__networksec_all__'"
        query = re.sub(r"\$\{([^}]+)\}", lambda match: substitutions[match[1]], raw_sql)
        name_only = EventFilters(
            start,
            end,
            device_name="R1",
            severity=EventSeverity.HIGH,
            category=Category.AUTHENTICATION,
        )
        assert (
            connection.execute(query).fetchone()[0]
            == storage.summary(name_only)["total_events"]
            == 7
        )


def test_roles_revocation_and_audit(tmp_path, backend):
    dsn, _ = backend
    with _client(tmp_path, dsn) as client:
        path = "/api/v1"
        assert client.post(path + "/devices", json={}).status_code == 401
        admin = _login(client)
        for username, role in (("observer", "viewer"), ("operator", "analyst")):
            response = client.post(
                path + "/users",
                headers=admin,
                json={
                    "username": username,
                    "role": role,
                    "password": "fixture password",
                },
            )
            assert response.status_code == 201, response.text
            assert "password" not in response.text
        viewer = _login(client, "observer", "fixture password")
        analyst = _login(client, "operator", "fixture password")
        assert client.get(path + "/dashboard/summary", headers=viewer).status_code == 200
        assert client.get(path + "/topology", headers=viewer).status_code == 200
        assert client.get(path + "/reports/export", headers=viewer).status_code == 200
        assert (
            client.get(path + "/reports/export?report=devices", headers=viewer).status_code == 403
        )
        assert client.get(path + "/events/catalog", headers=viewer).status_code == 403
        assert client.get(path + "/devices", headers=analyst).status_code == 200
        valid_device = {"name": "second", "device_type": "router"}
        assert client.post(path + "/devices", headers=analyst, json=valid_device).status_code == 403
        assert client.get(path + "/audit-logs", headers=analyst).status_code == 403
        assert (
            client.get(
                path + "/events/" + "1" * 64, headers=analyst, params={"include_raw": True}
            ).status_code
            == 403
        )
        assert (
            client.patch(
                path + "/users/observer", headers=analyst, json={"role": "admin"}
            ).status_code
            == 403
        )
        assert (
            client.patch(
                path + "/users/observer", headers=admin, json={"role": "analyst"}
            ).status_code
            == 200
        )
        assert client.get(path + "/auth/me", headers=viewer).status_code == 401
        assert client.post(path + "/auth/logout", headers=analyst).status_code == 204
        assert client.get(path + "/auth/me", headers=analyst).status_code == 401
        promoted = _login(client, "observer", "fixture password")
        reset = client.patch(
            path + "/users/observer", headers=admin, json={"password": "reset fixture password"}
        )
        assert reset.status_code == 200 and reset.json()["role"] == "analyst"
        assert client.get(path + "/auth/me", headers=promoted).status_code == 401
        assert _login(client, "observer", "reset fixture password")
        invalid = client.post(
            path + "/auth/login", json={"username": "nobody", "password": "fixture"}
        )
        assert invalid.status_code == 401
        rows = client.get(path + "/audit-logs", headers=admin).json()["items"]
        assert all(row["request_id"] for row in rows)
        assert any(
            row["action"] == "auth.login"
            and row["outcome"] == "failure"
            and row["actor_id"] is None
            for row in rows
        )
        assert any(row["action"] == "user.role" for row in rows)
        assert any(row["action"] == "user.password" and row["metadata"] == {} for row in rows)
    with _client(tmp_path, dsn) as restarted:
        assert restarted.get("/api/v1/auth/me", headers=admin).json()["role"] == "admin"


def test_operational_cookie_and_bearer_have_independent_lifecycles(tmp_path, backend):
    dsn, storage = backend
    with _client(tmp_path, dsn) as client:
        api = "/api/v1"
        admin = _login(client)
        for logout_path in ("/logout", api + "/auth/logout"):
            csrf = client.get("/login").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
            login = client.post(
                "/login",
                data={"username": "admin", "password": "test bootstrap password", "csrf": csrf},
                follow_redirects=False,
            )
            assert login.status_code == 303
            assert client.get(api + "/auth/me").json()["role"] == "admin"
            assert (
                client.get(
                    api + "/auth/me", headers={"Authorization": "Bearer invalid"}
                ).status_code
                == 401
            )
            assert client.get(api + "/users", headers=admin).status_code == 200
            assert client.post(api + "/auth/logout").status_code == 403
            with storage._connect() as connection:
                assert (
                    connection.execute("SELECT count(*) AS n FROM api_sessions").fetchone()["n"]
                    == 2
                )
            csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
            response = client.post(
                logout_path,
                headers={"X-CSRF-Token": csrf},
                data={"csrf": csrf} if logout_path == "/logout" else None,
                follow_redirects=False,
            )
            assert response.status_code == (303 if logout_path == "/logout" else 204)
            assert client.get(api + "/auth/me").status_code == 401
            assert client.get(api + "/auth/me", headers=admin).status_code == 200
            with storage._connect() as connection:
                assert (
                    connection.execute("SELECT count(*) AS n FROM api_sessions").fetchone()["n"]
                    == 1
                )


def test_catalog_failure_rolls_back_builtin_incident(tmp_path, backend, monkeypatch):
    _, storage = backend
    engine = CorrelationEngine.from_files(
        tmp_path / "correlation.db", Path("config/correlation_rules.yaml")
    )
    event = _event(datetime.now(UTC), EventType.LINK_DOWN)
    alert = engine.process(event).alert
    assert alert is not None

    def fail_projection(*_args):
        raise StorageError("injected interface projection failure")

    with monkeypatch.context() as patch:
        patch.setattr("app.storage.backend.record_interface_observation", fail_projection)
        with pytest.raises(StorageError, match="injected interface projection failure"):
            storage.record_event(event, "192.0.2.7", None, False, None, alert=alert)
    assert storage.event(event.event_id) is None
    assert storage.get_alert(alert.aggregate_id) is None
    for _ in range(2):
        storage.record_event(event, "192.0.2.7", None, False, None, alert=alert)
    assert storage.event(event.event_id) is not None
    assert storage.get_alert(alert.aggregate_id).count == 1


def test_managed_rules_incidents_and_out_of_order_recovery(tmp_path, backend):
    dsn, storage = backend
    now = datetime.fromtimestamp((int(datetime.now(UTC).timestamp()) // 60 - 1) * 60, UTC)
    with _client(tmp_path, dsn) as client:
        admin = _login(client)
        body = {
            "id": "test-recovery-rule",
            "enabled": True,
            "definition": {
                "name": "Threshold and recovery",
                "priority": 1,
                "event_types": ["port_security"],
                "recovery_types": ["configuration_change"],
                "group_by": ["device_name"],
                "window_seconds": 60,
                "threshold": 2,
                "severity": "critical",
                "category": "security",
            },
        }
        assert client.post("/api/v1/rules", headers=admin, json=body).status_code == 201
        assert client.post("/api/v1/rules", headers=admin, json=body).status_code == 409
        rule = "/api/v1/rules/test-recovery-rule"
        assert client.get(rule, headers=admin).json()["revision"] == 1
        assert any(
            row["id"] == body["id"] for row in client.get("/api/v1/rules", headers=admin).json()
        )
        saved = client.patch(rule, headers=admin, json={"enabled": True})
        assert saved.status_code == 200 and saved.json()["enabled"]
        assert client.post(rule + "/validate", headers=admin).json()["valid"]
        trigger = EventType.PORT_SECURITY
        recovery = _event(now + timedelta(seconds=5), EventType.CONFIGURATION_CHANGE, "recovery")
        fail1 = _event(now + timedelta(seconds=1), trigger, "matching 1")
        fail2 = _event(now + timedelta(seconds=2), trigger, "matching 2")
        samples = [item.model_dump(mode="json") for item in (recovery, fail2, fail1, fail1)]
        simulation = client.post(rule + "/test", headers=admin, json={"events": samples})
        assert simulation.status_code == 200, simulation.text
        assert simulation.json()[0]["recovered"]
        assert not client.get("/api/v1/reports/incidents", headers=admin).json()["items"]
        for event in (recovery, fail2, fail1, fail1):
            storage.record_event(event, "192.0.2.10", None, False, None, True)
        incidents = client.get("/api/v1/reports/incidents", headers=admin).json()["items"]
        assert len(incidents) == 1
        incident = incidents[0]["aggregate_id"]
        assert incidents[0]["count"] == 2 and incidents[0]["status"] == "resolved"
        fail3 = _event(now + timedelta(seconds=6), trigger, "matching 3")
        storage.record_event(fail3, "192.0.2.10", None, False, None, True)
        result = client.get(f"/api/v1/alerts/{incident}", headers=admin).json()
        assert result["count"] == 3 and result["status"] == "new"
        relations = client.get(f"/api/v1/events/{fail1.event_id}/related", headers=admin).json()
        assert relations["incident_ids"] == [incident]
        assert set(relations["related_event_ids"]) == {
            recovery.event_id,
            fail2.event_id,
            fail3.event_id,
        }
        change = client.patch(
            f"/api/v1/alerts/{incident}/status", headers=admin, json={"status": "resolved"}
        )
        assert change.status_code == 200, change.text
        audit = client.get("/api/v1/audit-logs?action=incident.status", headers=admin).json()[
            "items"
        ]
        assert audit[0]["request_id"] == change.headers["X-Request-ID"]
        assert client.delete(rule, headers=admin).status_code == 204
        assert client.get(rule, headers=admin).json()["enabled"] is False
        assert client.delete("/api/v1/rules/ospf-adjacency", headers=admin).status_code == 409


def test_topology_uses_configured_endpoints_and_unmapped_observations(backend):
    _, storage = backend
    config = OspfCorrelationConfig.model_validate(
        {
            "scope": "fixture",
            "links": [
                {
                    "id": "router-link",
                    "area": "0.0.0.0",
                    "endpoints": [
                        {"router_id": "192.0.2.1", "device_name": "R1", "interface_name": "ether2"},
                        {"router_id": "192.0.2.2", "device_name": "R2", "interface_name": "ether2"},
                    ],
                }
            ],
        }
    )
    now = datetime.now(UTC).replace(microsecond=0)
    inventory = TopologyInventory.model_validate(
        {
            "nodes": [
                {"name": "R1", "device_type": "router"},
                {"name": "VLAN10", "device_type": "segment"},
            ],
            "links": [{"id": "vlan10", "source": "R1", "target": "VLAN10", "link_type": "segment"}],
        }
    )

    def transition(name, local, peer, after, at):
        return NormalizedEvent(
            schema_version="1.1",
            timestamp=at,
            received_at=at,
            vendor="mikrotik",
            product="routeros",
            event_type="routing_neighbor_up" if after == "FULL" else "routing_neighbor_down",
            severity="medium",
            device_name=name,
            interface_name="ether2",
            outcome="success" if after == "FULL" else "failure",
            message="fixture",
            raw_message=name + after,
            parser_name="fixture",
            routing_protocol="ospf",
            ospf_area="0.0.0.0",
            local_router_id=local,
            neighbor_router_id=peer,
            previous_state="DOWN" if after == "FULL" else "FULL",
            current_state=after,
        )

    def compose():
        return build_topology(storage, config, inventory, include_addresses=False)

    first = compose()
    assert [link.status for link in first.links] == ["unknown", "unknown"]
    stable_id = first.links[1].id
    for event in (
        transition("R1", "192.0.2.1", "192.0.2.2", "FULL", now),
        transition("R2", "192.0.2.2", "192.0.2.1", "FULL", now),
        transition("R1", "192.0.2.1", "192.0.2.2", "DOWN", now - timedelta(seconds=2)),
        transition("R3", "192.0.2.3", "192.0.2.4", "DOWN", now),
    ):
        storage.record_event(event, None, None, False, config)
    final = compose()
    mapped = next(link for link in final.links if link.id == stable_id)
    assert mapped.status == "up" and mapped.kind == "observed"
    assert len(mapped.related_event_ids) == 2
    assert any(link.kind == "unmapped" and link.target is None for link in final.links)
    assert all(link.source in {node.id for node in final.nodes} for link in final.links)
