from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import BASE_DIR, Settings
from app.main import create_app
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import AggregatedAlert
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import (
    AlertPage,
    AlertQuery,
    EventPage,
    EventQuery,
    StorageUnavailableError,
)
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

    async def push_event(self, event: NormalizedEvent) -> None:
        return None

    async def query_events(self, query: EventQuery) -> EventPage:
        self.query = query
        return EventPage((_event(),), "next-page")

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


def _client(tmp_path: Path) -> tuple[TestClient, FakeLogStorage, FakeAlertStorage]:
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
