"""Regression coverage for Grafana links and published dashboard variable names."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest

from app.config import Settings
from app.schemas.backend import Category
from app.schemas.event import EventSeverity
from app.services.backend import EventFilters
from app.services.grafana import dashboard_link

START = datetime(2026, 10, 2, 12, tzinfo=UTC)
END = START + timedelta(minutes=15)
DEVICE_ID = UUID("52ecc148-ddb7-4fba-8b66-92b787b5e8fc")


def test_link_encodes_filters_and_matches_the_kpi_dashboard() -> None:
    settings = Settings(grafana_public_url="https://metrics.example.test/observability/")
    filters = EventFilters(
        START, END, DEVICE_ID, "Router A & B", EventSeverity.HIGH, Category.AUTHENTICATION
    )
    incident_id = "a" * 64
    link = dashboard_link(settings, filters, incident_id)
    assert link is not None
    url = urlsplit(link)
    assert url.path == "/observability/d/network-event-kpis"
    assert parse_qs(url.query) == {
        "from": [str(int(START.timestamp() * 1000))],
        "to": [str(int(END.timestamp() * 1000))],
        "var-device": ["Router A & B"],
        "var-device_id": [str(DEVICE_ID)],
        "var-severity": ["high"],
        "var-category": ["authentication"],
        "var-incident": [incident_id],
    }
    definition = Path("infra/grafana/dashboards/network-event-kpis.json").read_text(
        encoding="utf-8"
    )
    dashboard = json.loads(definition)
    assert dashboard["uid"] == "network-event-kpis"
    assert {variable["name"] for variable in dashboard["templating"]["list"]} == {
        key.removeprefix("var-") for key in parse_qs(url.query) if key.startswith("var-")
    }


def test_legacy_dashboard_uses_the_device_name_fallback_when_configured() -> None:
    settings = Settings(
        grafana_public_url="https://metrics.example.test",
        grafana_dashboard_uid="network-event-operations",
        grafana_variable_mapping="device=device,severity=severity",
    )
    link = dashboard_link(settings, EventFilters(START, END, DEVICE_ID), None, "Router A")
    assert link is not None
    assert parse_qs(urlsplit(link).query)["var-device"] == ["Router A"]


@pytest.mark.parametrize(
    "public_url",
    ("http://grafana:3000", "https://grafana-user@metrics.example.test", "file:///tmp/grafana"),
)
def test_link_rejects_unsuitable_public_addresses(public_url: str) -> None:
    with pytest.raises(ValueError, match="Invalid public Grafana URL"):
        dashboard_link(Settings(grafana_public_url=public_url), EventFilters(START, END), None)
