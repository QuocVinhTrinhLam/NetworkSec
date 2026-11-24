"""Fast regressions for transport, permissions and presentation boundaries."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.schemas.backend import Category
from app.schemas.event import EventSeverity
from app.services.backend import EventFilters, date_range, redact
from app.services.grafana import dashboard_link
from app.web.accounts import LoginThrottle
from app.web.body_limit import API_BODY_LIMIT
from scripts.export_openapi import build_spec


def test_configured_frontend_origin_and_body_limit(tmp_path: Path) -> None:
    origin = "https://custom-dashboard.example.test"
    app = create_app(
        Settings(
            database_path=tmp_path / "legacy.db",
            session_secret="synthetic",
            frontend_origins=(origin,),
        )
    )
    with TestClient(app) as client:
        headers = {
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        }
        approved = client.options("/api/v1/auth/login", headers={**headers, "Origin": origin})
        assert approved.status_code == 200
        assert approved.headers["Access-Control-Allow-Origin"] == origin
        assert "Access-Control-Allow-Credentials" not in approved.headers
        denied = client.options(
            "/api/v1/auth/login", headers={**headers, "Origin": "https://other.test"}
        )
        assert denied.status_code == 400
        assert "Access-Control-Allow-Origin" not in denied.headers
        excessive = client.post("/api/v1/auth/login", content=b"0" * (API_BODY_LIMIT + 1))
        assert excessive.status_code == 413
        assert excessive.headers["Cache-Control"] == "no-store"


def test_login_limit_is_bounded_per_source() -> None:
    throttle = LoginThrottle()
    assert all(throttle.allow("198.51.100.10") for _ in range(10))
    assert not throttle.allow("198.51.100.10")
    assert throttle.allow("198.51.100.11")


def test_grafana_link_quotes_filter_values_and_rejects_internal_host() -> None:
    start = datetime(2026, 11, 24, tzinfo=UTC)
    filters = EventFilters(
        start,
        start + timedelta(hours=1),
        UUID(int=1),
        "R1 & R2 #Ether2",
        EventSeverity.HIGH,
        Category.ROUTING,
    )
    settings = Settings(grafana_public_url="https://metrics.example.test/grafana/")
    result = dashboard_link(settings, filters, "a" * 64)
    assert result is not None
    parsed = urlsplit(result)
    assert parsed.path == "/grafana/d/network-event-kpis"
    assert parse_qs(parsed.query) == {
        "from": [str(int(start.timestamp() * 1000))],
        "to": [str(int((start + timedelta(hours=1)).timestamp() * 1000))],
        "var-device": ["R1 & R2 #Ether2"],
        "var-device_id": [str(UUID(int=1))],
        "var-severity": ["high"],
        "var-category": ["routing"],
        "var-incident": ["a" * 64],
    }
    with pytest.raises(ValueError, match="Invalid public Grafana URL"):
        dashboard_link(Settings(grafana_public_url="http://grafana:3000"), filters, None)


def test_redaction_and_bounded_utc_ranges() -> None:
    assert redact('user=operator "password":"fixture"') == 'user=operator "password":[REDACTED]'
    assert "fixture" not in redact("Authorization: Bearer fixture https://test:fixture@host")
    end = datetime(2026, 11, 24, tzinfo=UTC)
    assert date_range(None, end, "weekly") == (end - timedelta(days=7), end)
    with pytest.raises(ValueError):
        date_range(end - timedelta(days=91), end)


def test_frontend_spec_matches_routes_and_protected_operations(tmp_path: Path) -> None:
    generated = build_spec()
    artifact = Path("docs/openapi.json")
    assert json.loads(artifact.read_text(encoding="utf-8")) == generated
    app = create_app(Settings(database_path=tmp_path / "spec.db", session_secret="test-only"))
    runtime_paths = {
        path: methods
        for path, methods in app.openapi()["paths"].items()
        if path.startswith("/api/v1/")
    }
    assert runtime_paths == generated["paths"]
    identifiers = {
        "alert_id": "0" * 64,
        "event_id": "0" * 64,
        "device_id": str(UUID(int=1)),
        "rule_id": "fixture",
        "username": "fixture",
    }
    with TestClient(app) as client:
        for path, methods in generated["paths"].items():
            if path == "/api/v1/auth/login":
                assert not methods["post"].get("security")
                continue
            for method, operation in methods.items():
                assert operation["security"] == [{"HTTPBearer": []}]
                response = client.request(method, path.format(**identifiers))
                assert response.status_code == 401, (method, path, response.status_code)
    export = generated["paths"]["/api/v1/reports/export"]["get"]["responses"]["200"]
    assert set(export["content"]) == {"application/json", "text/csv"}
    assert {"X-Report-Truncated", "Content-Disposition"} <= set(export["headers"])
