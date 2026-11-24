from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import BASE_DIR, Settings
from app.main import create_app
from app.parsers import parse_syslog
from app.schemas.api import AlertLifecycleStatus, AlertRecord, StorageHealthResponse
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import (
    AlertEvidence,
    AlertPage,
    AlertQuery,
    EventPage,
    EventQuery,
    IncidentEventRef,
    StorageUnavailableError,
)
from app.storage.loki import LokiLogStorage
from app.web.auth import hash_password

BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
ALERT_ID = "a" * 64


def _event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME,
        received_at=BASE_TIME + timedelta(milliseconds=10),
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="core-sw-01",
        interface_name="GigabitEthernet0/1",
        interface_state="down",
        message="Interface changed state to down",
        raw_message="test event",
        parser_name="api-test",
    )


def _alert(status: AlertLifecycleStatus = AlertLifecycleStatus.NEW) -> AlertRecord:
    return AlertRecord(
        aggregate_id=ALERT_ID,
        rule_id="interface-link-state",
        event_family="link_state",
        device_name="core-sw-01",
        interface_name="GigabitEthernet0/1",
        event_types=(EventType.LINK_UP, EventType.LINK_DOWN),
        window_start=BASE_TIME,
        window_end=BASE_TIME + timedelta(minutes=1),
        count=100,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(seconds=50),
        severity=EventSeverity.HIGH,
        status=status,
        status_changed_at=BASE_TIME,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


class FakeLogStorage:
    def __init__(self) -> None:
        self.query: EventQuery | None = None
        self.events = (_event(),)

    async def push_event(self, event: NormalizedEvent) -> None:
        return None

    async def query_events(self, query: EventQuery) -> EventPage:
        self.query = query
        return EventPage(
            tuple(
                event
                for event in self.events
                if query.schema_version is None or event.schema_version == query.schema_version
            ),
            "next-page",
        )

    async def ready(self) -> bool:
        return True


class FakeAlertStorage:
    def __init__(self) -> None:
        self.query: AlertQuery | None = None
        self.record = _alert()
        self.migrated = False

    def migrate(self) -> None:
        self.migrated = True

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        return self.record

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        self.query = query
        return AlertPage((self.record,), 1)

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        return self.record if aggregate_id == ALERT_ID else None

    def get_alert_evidence(self, aggregate_id: str) -> AlertEvidence | None:
        if aggregate_id != ALERT_ID:
            return None
        ref = IncidentEventRef(_event().event_id, BASE_TIME, event_type=EventType.LINK_DOWN)
        return AlertEvidence(self.record, (ref,), ())

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        if aggregate_id != ALERT_ID:
            return None
        self.record = self.record.model_copy(
            update={
                "status": AlertLifecycleStatus.ACKNOWLEDGED,
                "acknowledged_by": actor,
                "acknowledged_at": BASE_TIME,
                "note": note,
            }
        )
        return self.record

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        if aggregate_id != ALERT_ID:
            return None
        self.record = self.record.model_copy(
            update={
                "status": AlertLifecycleStatus(status),
                "status_changed_by": actor,
                "note": note,
            }
        )
        return self.record

    def ready(self) -> bool:
        return True


def _client(
    tmp_path: Path, *, raise_server_exceptions: bool = True
) -> tuple[TestClient, FakeLogStorage, FakeAlertStorage]:
    logs = FakeLogStorage()
    alerts = FakeAlertStorage()
    settings = Settings(
        database_path=tmp_path / "api.db",
        severity_config=BASE_DIR / "config" / "severity.yaml",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        admin_username="admin",
        admin_password_hash=hash_password("test-password", iterations=10_000),
        session_secret="test-session-secret-with-enough-entropy",
    )
    return (
        TestClient(
            create_app(settings, log_storage=logs, alert_storage=alerts),
            follow_redirects=False,
            raise_server_exceptions=raise_server_exceptions,
        ),
        logs,
        alerts,
    )


def _login(client: TestClient) -> str:
    page = client.get("/login")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password", "csrf": token},
    )
    assert response.status_code == 303
    dashboard = client.get("/dashboard")
    return dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_api_requires_session_and_migrates_storage(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        assert alerts.migrated is True
        response = client.get("/api/v1/alerts")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Session"


def test_event_query_filters_and_pagination(tmp_path: Path) -> None:
    client, logs, _ = _client(tmp_path)
    with client:
        _login(client)
        response = client.get(
            "/api/v1/events",
            params={
                "start": BASE_TIME.isoformat(),
                "end": (BASE_TIME + timedelta(hours=1)).isoformat(),
                "severity": "high",
                "event_type": "link_down",
                "vendor": "cisco",
                "device_name": "core-sw-01",
                "interface_name": "GigabitEthernet0/1",
                "page_size": 25,
            },
        )
    assert response.status_code == 200
    assert response.json()["next_cursor"] == "next-page"
    assert len(response.json()["items"]) == 1
    assert logs.query is not None
    assert logs.query.limit == 25
    assert logs.query.severity is EventSeverity.HIGH
    assert logs.query.device_name == "core-sw-01"
    assert logs.query.schema_version == "1.0"
    assert "current_state" not in response.json()["items"][0]


def test_events_api_opts_into_ospf_with_legacy_items(tmp_path: Path) -> None:
    client, logs, _ = _client(tmp_path)
    fixture = BASE_DIR / "fixtures" / "logs" / "cisco-ospf-synthetic.log"
    raw = fixture.read_text(encoding="utf-8").splitlines()[1]
    ospf = parse_syslog(raw, received_at=BASE_TIME, source_host="R2").event
    assert ospf is not None
    logs.events = (_event(), ospf)

    with client:
        _login(client)
        default = client.get("/api/v1/events")
        extended = client.get("/api/v1/events", params={"include_ospf": True})

    assert default.status_code == extended.status_code == 200
    safe_legacy = _event().model_dump(mode="json", exclude={"raw_message"})
    safe_ospf = ospf.model_dump(mode="json", exclude={"raw_message"})
    assert default.json()["items"] == [{**safe_legacy, "raw_message": "[restricted]"}]
    assert extended.json()["schema_version"] == "1.0"
    assert extended.json()["items"] == [
        {**safe_legacy, "raw_message": "[restricted]"},
        {**safe_ospf, "raw_message": "[restricted]"},
    ]
    assert extended.json()["items"][1]["current_state"] == "FULL"
    assert logs.query is not None and logs.query.schema_version is None


def test_alert_api_default_queue_includes_old_active_alerts(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        _login(client)
        assert client.get("/api/v1/alerts?status=acknowledged").status_code == 200
        assert alerts.query is not None and alerts.query.include_active_before_start
        assert (
            client.get("/api/v1/alerts", params={"start": BASE_TIME.isoformat()}).status_code == 200
        )
        assert alerts.query is not None and not alerts.query.include_active_before_start


def test_alert_evidence_is_an_authenticated_additive_endpoint(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    path = f"/api/v1/alerts/{ALERT_ID}"
    with client:
        assert client.get(path + "/evidence").status_code == 401
        _login(client)
        detail = client.get(path)
        evidence = client.get(path + "/evidence")
        assert client.get(f"/api/v1/alerts/{'0' * 64}/evidence").status_code == 404
        assert client.get("/api/v1/alerts/invalid/evidence").status_code == 422

    assert detail.json() == alerts.record.model_dump(mode="json")
    assert evidence.status_code == 200
    data = evidence.json()
    assert data["schema_version"] == "1.0" and data["alert_id"] == ALERT_ID
    assert data["event_refs"][0]["event_id"] == _event().event_id
    assert data["event_refs"][0]["event_type"] == "link_down"
    assert data["ospf"] is None and data["history"] == []


def test_alert_api_accepts_operational_metadata_filters(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        _login(client)
        response = client.get(
            "/api/v1/alerts",
            params={"source_ip": "2001:0db8::1", "rule_id": "interface-link-state", "search": "%_"},
        )
        assert client.get("/api/v1/alerts?source_ip=not-an-address").status_code == 422
        assert client.get("/api/v1/alerts", params={"search": "invalid\x00name"}).status_code == 422
        assert client.get("/api/v1/alerts", params={"page": 1001}).status_code == 422
        assert (
            client.get("/api/v1/alerts", params={"end": "0001-01-01T00:00:00Z"}).status_code == 422
        )

    assert response.status_code == 200
    assert alerts.query is not None
    assert alerts.query.source_ip == "2001:db8::1"
    assert alerts.query.rule_id == "interface-link-state" and alerts.query.search == "%_"


def test_alert_query_acknowledgement_and_status_update(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        csrf = _login(client)
        listed = client.get(
            "/api/v1/alerts",
            params={
                "start": BASE_TIME.isoformat(),
                "end": (BASE_TIME + timedelta(hours=1)).isoformat(),
                "severity": "high",
                "status": "new",
                "page": 1,
                "page_size": 20,
            },
        )
        forbidden = client.post(
            f"/api/v1/alerts/{ALERT_ID}/acknowledge", json={"note": "investigating"}
        )
        acknowledged = client.post(
            f"/api/v1/alerts/{ALERT_ID}/acknowledge",
            json={"note": "investigating"},
            headers={"X-CSRF-Token": csrf},
        )
        resolved = client.patch(
            f"/api/v1/alerts/{ALERT_ID}/status",
            json={"status": "resolved", "note": "link stable"},
            headers={"X-CSRF-Token": csrf},
        )

    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["count"] == 100
    assert listed.json()["items"][0]["first_seen"] == BASE_TIME.isoformat().replace("+00:00", "Z")
    assert listed.json()["items"][0]["last_seen"].startswith("2026-01-01T12:00:50")
    assert listed.json()["items"][0]["status"] == "new"
    assert alerts.query is not None
    assert alerts.query.status == "new"
    assert alerts.query.page_size == 20
    assert forbidden.status_code == 403
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged_by"] == "admin"
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"


def test_api_validates_time_range_ids_and_payloads(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    with client:
        csrf = _login(client)
        reversed_range = client.get(
            "/api/v1/events",
            params={"start": BASE_TIME.isoformat(), "end": BASE_TIME.isoformat()},
        )
        invalid_id = client.get("/api/v1/alerts/not-an-alert-id")
        extra_field = client.patch(
            f"/api/v1/alerts/{ALERT_ID}/status",
            json={"status": "resolved", "unexpected": True},
            headers={"X-CSRF-Token": csrf},
        )

    assert reversed_range.status_code == 422
    assert invalid_id.status_code == 422
    assert extra_field.status_code == 422


def test_api_normalizes_backend_unavailable_errors(tmp_path: Path) -> None:
    client, logs, alerts = _client(tmp_path)

    async def unavailable_events(query: EventQuery) -> EventPage:
        raise StorageUnavailableError("internal Loki connection detail")

    def unavailable_alerts(query: AlertQuery) -> AlertPage:
        raise StorageUnavailableError("internal PostgreSQL connection detail")

    logs.query_events = unavailable_events  # type: ignore[method-assign]
    alerts.query_alerts = unavailable_alerts  # type: ignore[method-assign]
    with client:
        _login(client)
        event_response = client.get("/api/v1/events")
        alert_response = client.get("/api/v1/alerts")

    assert event_response.status_code == 503
    assert event_response.json() == {"detail": "Loki is unavailable"}
    assert alert_response.status_code == 503
    assert alert_response.json() == {"detail": "PostgreSQL is unavailable"}


def test_qa01_events_api_rejects_malformed_and_expired_cursors(tmp_path: Path) -> None:
    client, logs, _ = _client(tmp_path)

    def unexpected(request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid cursor must be rejected before querying Loki")

    async def query_events(query: EventQuery) -> EventPage:
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as loki_client:
            return await LokiLogStorage("http://mock.invalid", client=loki_client).query_events(
                query
            )

    logs.query_events = query_events  # type: ignore[method-assign]
    expired = {
        "timestamp_ns": int(BASE_TIME.timestamp()) * 1_000_000_000 - 1,
        "before_id": "1" * 64,
    }
    expired_token = base64.urlsafe_b64encode(json.dumps(expired).encode()).decode().rstrip("=")
    with client:
        _login(client)
        for token, detail in (
            ("invalid!", "invalid event pagination cursor"),
            (expired_token, "event pagination cursor is outside the query range"),
        ):
            response = client.get(
                "/api/v1/events",
                params={
                    "start": BASE_TIME.isoformat(),
                    "end": (BASE_TIME + timedelta(seconds=1)).isoformat(),
                    "cursor": token,
                },
            )
            assert response.status_code == 400
            assert response.json() == {"detail": detail}


def test_qa03_events_api_reports_protocol_failure_without_upstream_payload(tmp_path: Path) -> None:
    client, logs, _ = _client(tmp_path)

    async def query_events(query: EventQuery) -> EventPage:
        transport = httpx.MockTransport(
            lambda _: httpx.Response(200, json=["synthetic-upstream-marker"])
        )
        async with httpx.AsyncClient(transport=transport) as loki_client:
            return await LokiLogStorage("http://mock.invalid", client=loki_client).query_events(
                query
            )

    logs.query_events = query_events  # type: ignore[method-assign]
    with client:
        _login(client)
        response = client.get("/api/v1/events")
    assert response.status_code == 502
    assert response.json() == {"detail": "Loki query failed"}


def test_qa_http_route_authentication_and_public_contracts(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    item = f"/api/v1/alerts/{ALERT_ID}"
    with client:
        assert client.get("/health").json() == {"status": "ok", "mode": "mock"}
        assert client.get("/login").status_code == 200
        for path in (
            "/",
            "/dashboard",
            "/partials/dashboard",
            "/alerts",
            "/alerts/export.csv",
            f"/alerts/{ALERT_ID}",
            "/events",
            "/devices",
            "/scenarios",
            "/scenarios/export.csv",
        ):
            response = client.get(path)
            assert response.status_code == 303 and response.headers["location"] == "/login", path
        for path, data in (
            ("/logout", {"csrf": "invalid"}),
            (f"/alerts/{ALERT_ID}/ack", {"csrf": "invalid"}),
            (f"/alerts/{ALERT_ID}/resolve", {"csrf": "invalid"}),
            (
                "/scenarios",
                {"csrf": "invalid", "technique": "QA", "tool": "QA", "expected_rule": "QA"},
            ),
        ):
            assert client.post(path, data=data).status_code == 303, path
        protected = (
            ("GET", "/api/v1/storage/health"),
            ("GET", "/api/v1/events"),
            ("GET", "/api/v1/alerts"),
            ("GET", item),
            ("GET", item + "/evidence"),
            ("POST", item + "/acknowledge"),
            ("PATCH", item + "/status"),
        )
        for method, path in protected:
            response = client.request(method, path, json={"status": "resolved"})
            assert response.status_code == 401 and response.headers["www-authenticate"] == "Session"
        for path in (
            "/docs",
            "/redoc",
            "/docs/oauth2-redirect",
            "/openapi.json",
            "/static/styles.css",
        ):
            assert client.get(path).status_code == 200, path


def test_qa_api_validation_credentials_and_diagnostic_redaction(tmp_path: Path) -> None:
    client, logs, alerts = _client(tmp_path)

    async def log_not_ready() -> bool:
        return False

    logs.ready = log_not_ready  # type: ignore[method-assign]
    item = f"/api/v1/alerts/{ALERT_ID}"
    unknown = "/api/v1/alerts/" + "e" * 64
    with client:
        login = client.get("/login")
        assert "frame-ancestors 'none'" in login.headers["content-security-policy"]
        assert login.headers["x-content-type-options"] == "nosniff"
        cookie = login.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie
        token = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        bad = client.post(
            "/login", data={"username": "unknown", "password": "qa-invalid", "csrf": token}
        )
        assert bad.status_code == 401
        assert "qa-invalid" not in bad.text
        csrf = _login(client)
        assert csrf != token
        health = client.get("/api/v1/storage/health")
        snapshot = StorageHealthResponse.model_validate(health.json())
        assert (snapshot.status, snapshot.loki, snapshot.postgres) == (
            "degraded",
            "unavailable",
            "ready",
        )
        assert client.get(item).json()["aggregate_id"] == ALERT_ID
        assert client.get(unknown).status_code == 404
        assert client.get(unknown + "/evidence").status_code == 404
        assert client.get("/api/v1/alerts?page=0").status_code == 422
        assert client.get("/api/v1/events?page_size=501").status_code == 422
        assert client.get("/api/v1/events?vendor=unknown").status_code == 422
        headers = {"X-CSRF-Token": csrf}
        assert client.patch(item + "/status", json={"status": "resolved"}).status_code == 403
        assert (
            client.post(
                item + "/acknowledge",
                headers=headers | {"Content-Type": "application/json"},
                content="{",
            ).status_code
            == 422
        )
        assert (
            client.post(
                item + "/acknowledge", headers=headers, json={"note": "x" * 1001}
            ).status_code
            == 422
        )
        assert client.patch(item + "/status", headers=headers, json={}).status_code == 422
        assert client.post(unknown + "/acknowledge", headers=headers, json={}).status_code == 404
        assert (
            client.patch(
                unknown + "/status", headers=headers, json={"status": "resolved"}
            ).status_code
            == 404
        )
        assert alerts.record.status is AlertLifecycleStatus.NEW
        assert client.post("/logout", data={"csrf": csrf}).status_code == 303
        assert client.get(item).status_code == 401


def test_qa_non_ascii_csrf_gets_normal_forbidden_response(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path, raise_server_exceptions=False)
    with client:
        client.get("/login")
        response = client.post(
            "/login", data={"username": "guest", "password": "qa-placeholder", "csrf": "é"}
        )
    assert response.status_code == 403


def test_qa02_csrf_blocks_invalid_or_missing_tokens_on_web_and_api(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        assert client.get("/login").status_code == 200
        credentials = {"username": "admin", "password": "test-password"}
        for submitted in ({}, {"csrf": ""}, {"csrf": "wrong"}, {"csrf": "e\u0301"}, {"csrf": "😀"}):
            response = client.post("/login", data=credentials | submitted)
            assert response.status_code == 403
            assert response.json() == {"detail": "Invalid CSRF token"}
            assert client.get(f"/api/v1/alerts/{ALERT_ID}").status_code == 401

        csrf = _login(client)
        path = f"/alerts/{ALERT_ID}"
        for route, data in (
            ("/logout", {}),
            (path + "/ack", {}),
            (path + "/resolve", {}),
            ("/scenarios", {"technique": "QA", "tool": "QA", "expected_rule": "QA"}),
        ):
            assert client.post(route, data=data).status_code == 403
        api_ack = f"/api/v1{path}/acknowledge"
        for headers in ({}, {"X-CSRF-Token": "wrong"}, [(b"x-csrf-token", b"\xff")]):
            assert client.post(api_ack, headers=headers, json={}).status_code == 403
        assert alerts.record.status is AlertLifecycleStatus.NEW
        response = client.post(api_ack, headers={"X-CSRF-Token": csrf}, json={})
        assert response.status_code == 200 and response.json()["status"] == "acknowledged"
        assert client.post("/logout", data={"csrf": csrf}).status_code == 303


def test_qa_malformed_session_cookie_grants_no_access(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    with client:
        client.cookies.set("session", "qa-invalid-session-format")
        assert client.get("/api/v1/alerts").status_code == 401
        assert client.get("/dashboard").headers["location"] == "/login"


def test_qa_validation_error_does_not_echo_login_password(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    with client:
        login = client.get("/login")
        token = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        marker = "QA_SYNTHETIC_LOGIN_FIELD_"
        response = client.post(
            "/login",
            data={"username": "qa-placeholder", "password": marker + "x" * 1024, "csrf": token},
        )
    assert response.status_code == 422
    assert marker not in response.text, "422 response contains the synthetic password marker"


def test_qa06_validation_keeps_all_errors_without_secret_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, _, alerts = _client(tmp_path)
    marker = "QA_SYNTHETIC_PRIVATE_VALUE"
    with client:
        login = client.get("/login")
        token = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        oversized = client.post(
            "/login",
            data={"username": "u" * 101, "password": marker + "x" * 1024, "csrf": token},
        )
        csrf = _login(client)
        ack = f"/api/v1/alerts/{ALERT_ID}/acknowledge"
        headers = {"X-CSRF-Token": csrf}
        invalid = client.post(
            ack,
            headers=headers,
            json={"note": {"password": marker, "token": marker}, "session_secret": marker},
        )
        malformed = client.post(
            ack,
            headers=headers | {"Content-Type": "application/json"},
            content='{"password":"' + marker,
        )
        assert alerts.record.status is AlertLifecycleStatus.NEW
        assert client.post(ack, headers=headers, json={}).status_code == 200

    for response in (oversized, invalid, malformed):
        assert response.status_code == 422 and marker not in response.text
        assert all(set(item) == {"loc", "msg", "type"} for item in response.json()["detail"])
    assert {tuple(error["loc"]): error["type"] for error in oversized.json()["detail"]} == {
        ("body", "username"): "string_too_long",
        ("body", "password"): "string_too_long",
    }
    assert {tuple(error["loc"]): error["type"] for error in invalid.json()["detail"]} == {
        ("body", "note"): "string_type",
        ("body", "session_secret"): "extra_forbidden",
    }
    assert malformed.json()["detail"][0]["type"] == "json_invalid"
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
