from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
from app.storage.base import AlertPage, AlertQuery, EventPage, EventQuery
from app.web.auth import hash_password

NOW = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
ALERT_ID = "c" * 64


def _event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=NOW,
        received_at=NOW,
        vendor=EventVendor.CISCO,
        product="IOS",
        event_type=EventType.LINK_DOWN,
        severity=EventSeverity.HIGH,
        outcome=EventOutcome.UNKNOWN,
        device_name="core-sw-01",
        interface_name="Gi0/1",
        message="Interface state changed to down",
        raw_message="phase6 normalized raw",
        parser_name="phase6-ui-test",
    )


def _alert(status: AlertLifecycleStatus = AlertLifecycleStatus.NEW) -> AlertRecord:
    return AlertRecord(
        aggregate_id=ALERT_ID,
        rule_id="interface-link-state",
        event_family="link_state",
        device_name="core-sw-01",
        interface_name="Gi0/1",
        event_types=(EventType.LINK_UP, EventType.LINK_DOWN),
        window_start=NOW - timedelta(minutes=1),
        window_end=NOW,
        count=100,
        first_seen=NOW - timedelta(seconds=50),
        last_seen=NOW,
        severity=EventSeverity.HIGH,
        status=status,
        status_changed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


class DashboardLogs:
    def __init__(self) -> None:
        self.last_query: EventQuery | None = None

    async def push_event(self, event: NormalizedEvent) -> None:
        return None

    async def query_events(self, query: EventQuery) -> EventPage:
        self.last_query = query
        return EventPage((_event(),), "next-cursor" if query.limit == 50 else None)

    async def ready(self) -> bool:
        return True


class DashboardAlerts:
    def __init__(self) -> None:
        self.record = _alert()
        self.last_query: AlertQuery | None = None

    def migrate(self) -> None:
        return None

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        return self.record

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        self.last_query = query
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
                "acknowledged_at": NOW,
            }
        )
        return self.record

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        return self.record

    def dashboard_stats(self, start: datetime, end: datetime) -> dict[str, Any]:
        return {
            "total": 1,
            "severity": [{"label": "high", "value": 1}],
            "timeline": [{"label": "2026-11-19 08:00", "value": 1}],
            "device_types": [{"label": "core-sw-01", "value": 1}],
            "top_devices": [{"label": "core-sw-01", "value": 1}],
            "top_sources": [],
            "top_rules": [{"label": "interface-link-state — link_state", "value": 1}],
            "event_types": [{"label": "link_down", "value": 1}],
        }

    def claim_notifications(
        self, minimum_severity: EventSeverity, now: datetime, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        return ()

    def get_telegram_message_id(self, aggregate_id: str, chat_id: int) -> int | None:
        return None

    def save_telegram_message_id(self, aggregate_id: str, chat_id: int, message_id: int) -> None:
        return None

    def ready(self) -> bool:
        return True


def _client(tmp_path: Path) -> tuple[TestClient, DashboardLogs, DashboardAlerts]:
    logs = DashboardLogs()
    alerts = DashboardAlerts()
    settings = Settings(
        database_path=tmp_path / "dashboard.db",
        severity_config=BASE_DIR / "config" / "severity.yaml",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        dashboard_backend="operational",
        admin_username="admin",
        admin_password_hash=hash_password("test-password", iterations=10_000),
        session_secret="test-session-secret-with-enough-entropy",
        mock_mode=False,
    )
    app = create_app(settings, log_storage=logs, alert_storage=alerts)
    return TestClient(app, follow_redirects=False), logs, alerts


def _login(client: TestClient) -> str:
    page = client.get("/login")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert (
        client.post(
            "/login",
            data={"username": "admin", "password": "test-password", "csrf": token},
        ).status_code
        == 303
    )
    dashboard = client.get("/dashboard")
    return dashboard.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_operational_dashboard_reuses_ui_with_alerts_and_events(tmp_path: Path) -> None:
    client, _, _ = _client(tmp_path)
    with client:
        _login(client)
        dashboard = client.get("/dashboard")

    assert dashboard.status_code == 200
    assert "Network Event Dashboard" in dashboard.text
    assert "Operational storage" in dashboard.text
    assert "Recent events" in dashboard.text
    assert "Link Down" in dashboard.text
    assert "core-sw-01" in dashboard.text
    assert "100" in dashboard.text


def test_operational_alert_and_event_filters_reach_storage(tmp_path: Path) -> None:
    client, logs, alerts = _client(tmp_path)
    with client:
        _login(client)
        alert_page = client.get(
            "/alerts?time_range=24&device=core-sw-01&severity=high&event_type=link_down&status=new"
        )
        event_page = client.get(
            "/events?time_range=24&device=core-sw-01&severity=high"
            "&event_type=link_down&vendor=cisco"
        )

    assert alert_page.status_code == 200
    assert "100 events" in alert_page.text
    assert "First / last seen" in alert_page.text
    assert "New" in alert_page.text
    assert alerts.last_query is not None
    assert alerts.last_query.device_name == "core-sw-01"
    assert alerts.last_query.event_type is EventType.LINK_DOWN
    assert alerts.last_query.status == "new"
    assert event_page.status_code == 200
    assert "Normalized events" in event_page.text
    assert "phase6 normalized raw" not in event_page.text
    assert logs.last_query is not None
    assert logs.last_query.vendor is EventVendor.CISCO
    assert logs.last_query.severity is EventSeverity.HIGH


def test_operational_alert_detail_and_acknowledgement(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    with client:
        csrf = _login(client)
        detail = client.get(f"/alerts/{ALERT_ID}")
        acknowledged = client.post(
            f"/alerts/{ALERT_ID}/ack",
            data={"csrf": csrf},
        )

    assert detail.status_code == 200
    assert "Event count" in detail.text
    assert "First seen" in detail.text
    assert "Last seen" in detail.text
    assert acknowledged.status_code == 303
    assert alerts.record.status is AlertLifecycleStatus.ACKNOWLEDGED
