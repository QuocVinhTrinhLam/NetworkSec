from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import BASE_DIR, Settings
from app.main import create_app
from app.schemas.api import AlertLifecycleStatus, AlertRecord
from app.schemas.correlation import AggregatedAlert, OspfAdjacencyKey, OspfReporterState
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)
from app.storage.base import (
    AlertEvidence,
    AlertListMetadata,
    AlertPage,
    AlertQuery,
    AlertQueueSummary,
    AlertStatusChange,
    EventPage,
    EventQuery,
    IncidentEventRef,
    OspfIncidentRecord,
)
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
        self.total = 1
        self.metadata = AlertListMetadata()
        self.incident: OspfIncidentRecord | None = None
        self.history = (
            AlertStatusChange(None, AlertLifecycleStatus.NEW, "system", None, None, NOW),
        )

    def migrate(self) -> None:
        return None

    def upsert_alert(self, alert: AggregatedAlert, event: NormalizedEvent) -> AlertRecord:
        return self.record

    def query_alerts(self, query: AlertQuery) -> AlertPage:
        self.last_query = query
        return AlertPage((self.record,), self.total, {ALERT_ID: self.metadata})

    def get_alert(self, aggregate_id: str) -> AlertRecord | None:
        return self.record if aggregate_id == ALERT_ID else None

    def get_alert_evidence(self, aggregate_id: str) -> AlertEvidence | None:
        if aggregate_id != ALERT_ID:
            return None
        refs = (
            self.incident.event_refs
            if self.incident
            else (IncidentEventRef(_event().event_id, NOW, event_type=EventType.LINK_DOWN),)
        )
        return AlertEvidence(self.record, refs, self.history, self.incident)

    def acknowledge(self, aggregate_id: str, actor: str, note: str | None) -> AlertRecord | None:
        return self.update_status(aggregate_id, AlertLifecycleStatus.ACKNOWLEDGED, actor, note)

    def update_status(
        self, aggregate_id: str, status: str, actor: str, note: str | None
    ) -> AlertRecord | None:
        if aggregate_id != ALERT_ID:
            return None
        new_state = AlertLifecycleStatus(status)
        self.history += (
            AlertStatusChange(self.record.status, new_state, "operator", actor, note, NOW),
        )
        update = {"status": new_state, "note": note}
        if new_state is AlertLifecycleStatus.ACKNOWLEDGED:
            update |= {"acknowledged_by": actor, "acknowledged_at": NOW}
        self.record = self.record.model_copy(update=update)
        return self.record

    def queue_summary(self, start: datetime, end: datetime) -> AlertQueueSummary:
        return AlertQueueSummary(new=1, acknowledged=0, high_priority=1, recently_resolved=0)

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


def test_operational_dashboard_shows_workflow_without_querying_event_telemetry(
    tmp_path: Path,
) -> None:
    client, logs, _ = _client(tmp_path)
    with client:
        _login(client)
        dashboard = client.get("/dashboard")
        partial = client.get("/partials/dashboard")

    assert dashboard.status_code == 200
    assert "Incident Dashboard" in dashboard.text
    assert "Operational storage" in dashboard.text
    assert "Recent alerts" in dashboard.text
    assert 'id="timeline-chart"' not in dashboard.text
    assert "High priority" in partial.text
    assert "core-sw-01" in dashboard.text
    assert "100" in dashboard.text
    assert logs.last_query is None


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
    assert alerts.last_query.include_active_before_start
    assert event_page.status_code == 200
    assert "Normalized events" in event_page.text
    assert "phase6 normalized raw" not in event_page.text
    assert logs.last_query is not None
    assert logs.last_query.vendor is EventVendor.CISCO
    assert logs.last_query.severity is EventSeverity.HIGH


def test_operational_alert_detail_evidence_and_actions_require_session_and_csrf(
    tmp_path: Path,
) -> None:
    client, logs, alerts = _client(tmp_path)
    adjacency = OspfAdjacencyKey.model_validate(
        {
            "scope": "lab",
            "area": "0.0.0.0",
            "router_ids": ["192.0.2.1", "192.0.2.2"],
            "link_id": "r1-r2",
        }
    )
    evidence_event = _event()
    alerts.incident = OspfIncidentRecord(
        adjacency,
        None,
        None,
        (OspfReporterState(router_id=adjacency.router_ids[0], last_down_at=NOW),),
        (
            IncidentEventRef(
                evidence_event.event_id,
                NOW,
                adjacency.router_ids[0],
                EventType.ROUTING_NEIGHBOR_DOWN,
            ),
        ),
    )
    alerts.metadata = AlertListMetadata(adjacency)
    detail_url = f"/alerts/{ALERT_ID}"
    with client:
        assert client.get(detail_url).headers["location"] == "/login"
        assert client.post(detail_url + "/resolve", data={"csrf": "wrong"}).headers["location"] == (
            "/login"
        )
        csrf = _login(client)
        queue = client.get("/alerts")
        detail = client.get(detail_url)
        assert client.post(detail_url + "/ack", data={"csrf": "wrong"}).status_code == 403
        assert client.post(detail_url + "/resolve", data={"csrf": "wrong"}).status_code == 403
        acknowledged = client.post(
            detail_url + "/ack",
            data={"csrf": csrf, "note": "<script>check</script>"},
        )
        resolved = client.post(detail_url + "/resolve", data={"csrf": csrf, "note": "Field repair"})
        finished = client.get(detail_url)
        evidence = client.get(
            "/events",
            params={"event_id": evidence_event.event_id, "event_at": NOW.isoformat()},
        )

    assert "192.0.2.1 ↔ 192.0.2.2" in queue.text
    assert detail.status_code == 200
    assert "Event count" in detail.text
    assert "First seen" in detail.text
    assert "Last seen" in detail.text
    assert "OSPF adjacency" in detail.text and "0.0.0.0" in detail.text
    assert "Awaiting confirmed Full" in detail.text
    assert "Incident timeline" in detail.text and "Related event evidence" in detail.text
    assert acknowledged.status_code == 303
    assert resolved.status_code == 303
    assert alerts.record.status is AlertLifecycleStatus.RESOLVED
    assert alerts.record.acknowledged_by == "admin"
    assert "Field repair" in finished.text and "&lt;script&gt;check&lt;/script&gt;" in finished.text
    assert "phase6 normalized raw" in evidence.text
    assert logs.last_query is not None and logs.last_query.event_id == evidence_event.event_id


def test_operational_csv_and_pagination_keep_all_filters(tmp_path: Path) -> None:
    client, _, alerts = _client(tmp_path)
    alerts.record = alerts.record.model_copy(update={"device_name": "=danger"})
    alerts.metadata = AlertListMetadata(source_ips=("192.0.2.88",))
    alerts.total = 51
    filters = {
        "page": "2",
        "rule_id": "interface-link-state",
        "source_ip": "192.0.2.88",
        "search": "filter & keep",
        "status": "new",
        "event_type": "link_down",
    }
    with client:
        assert client.get("/alerts/export.csv").headers["location"] == "/login"
        _login(client)
        page = client.get("/alerts", params=filters)
        query = alerts.last_query
        assert client.get("/alerts/export.csv?source_ip=invalid").status_code == 422
        export = client.get("/alerts/export.csv", params=filters)

    assert page.status_code == export.status_code == 200
    assert "rule_id=interface-link-state&amp;source_ip=192.0.2.88" in page.text
    assert "search=filter+%26+keep" in page.text and "&amp;page=3" in page.text
    assert query is not None and query.page == 2 and query.page_size == 25
    assert query.source_ip == "192.0.2.88" and query.search == "filter & keep"
    assert alerts.last_query is not None and alerts.last_query.page == 1
    assert alerts.last_query.rule_id == "interface-link-state"
    assert alerts.last_query.status == "new" and alerts.last_query.event_type is EventType.LINK_DOWN
    rows = list(csv.DictReader(io.StringIO(export.text)))
    assert rows[0]["id"] == ALERT_ID and rows[0]["source_ip"] == "192.0.2.88"
    assert rows[0]["device_name"] == "'=danger"
    assert export.headers["x-export-truncated"] == "true"
