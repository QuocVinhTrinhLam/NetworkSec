from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import BASE_DIR, Settings
from app.main import create_app
from app.models import Alert
from app.web.auth import hash_password


def build_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        database_path=tmp_path / "web.db",
        severity_config=BASE_DIR / "config" / "severity.yaml",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        admin_username="admin",
        admin_password_hash=hash_password("test-password", iterations=10_000),
        session_secret="test-session-secret-with-enough-entropy",
        mock_mode=True,
    )
    app = create_app(settings)
    app.state.database.insert_alert(
        Alert(
            id="web-alert",
            timestamp="2020-01-01T10:00:00+00:00",
            device_name='=HYPERLINK("https://attacker.invalid")',
            device_type="firewall",
            source_ip="203.0.113.5",
            dest_ip="10.0.0.1",
            user=None,
            rule_id="100201",
            rule_description="Port scan <img src=x>",
            severity="high",
            mitre_id="T1046",
            mitre_name="Discovery",
            raw_log="<script>owned()</script>",
        )
    )
    return TestClient(app, follow_redirects=False)


def login(client: TestClient) -> None:
    page = client.get("/login")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password", "csrf": token},
    )
    assert response.status_code == 303


def test_authentication_csrf_and_output_escaping(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        assert client.get("/dashboard").status_code == 303
        client.get("/login")
        assert (
            client.post(
                "/login", data={"username": "admin", "password": "test-password", "csrf": "bad"}
            ).status_code
            == 403
        )
        login(client)
        detail = client.get("/alerts/web-alert")
        assert detail.status_code == 200
        assert "<script>owned()" not in detail.text
        assert "&lt;script&gt;owned()&lt;/script&gt;" in detail.text


def test_alert_filters_and_csv_export(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/alerts?time_range=all&severity=high&source_ip=203.0.113.5")
        assert page.status_code == 200
        assert "web-alert" in page.text
        csv_response = client.get("/alerts/export.csv?time_range=all&severity=high")
        assert csv_response.status_code == 200
        assert "web-alert" in csv_response.text
        assert "'=HYPERLINK" in csv_response.text


def test_device_becomes_silent(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/devices")
        assert page.status_code == 200
        assert "silent" in page.text


def test_dashboard_renders_soc_command_center_and_live_queue(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        client.app.state.database.insert_alert(
            Alert(
                id="live-critical-alert",
                timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
                device_name="edge-fw-01",
                device_type="firewall",
                source_ip="198.51.100.23",
                dest_ip="10.0.0.10",
                user="soc-analyst",
                rule_id="100900",
                rule_description='Suspicious </script><script>alert("owned")</script> access',
                severity="critical",
                mitre_id="T1078",
                mitre_name="Valid Accounts",
                raw_log="authentication anomaly",
            )
        )
        login(client)

        page = client.get("/dashboard")

        assert page.status_code == 200
        assert "SOC Command Center" in page.text
        assert 'aria-label="Primary navigation"' in page.text
        assert 'aria-current="page"' in page.text
        assert "Investigation queue" in page.text
        assert "live-critical-alert" in page.text
        assert "edge-fw-01" in page.text
        assert '</script><script>alert("owned")</script>' not in page.text

        partial = client.get("/partials/dashboard")
        assert partial.status_code == 200
        assert '</script><script>alert("owned")</script>' not in partial.text


def test_attack_scenario_requires_csrf_and_exports_csv(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/scenarios")
        token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        response = client.post(
            "/scenarios",
            data={
                "csrf": token,
                "technique": "Network Service Scanning",
                "tool": "nmap",
                "expected_rule": "100201",
                "detected": "true",
                "detection_time_seconds": "8.4",
                "notes": "Detected in mock mode",
            },
        )
        assert response.status_code == 303
        exported = client.get("/scenarios/export.csv")
        assert "Network Service Scanning" in exported.text
