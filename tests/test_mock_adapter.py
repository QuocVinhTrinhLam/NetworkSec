import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.adapters.mock import DEFAULT_FIXTURES, SCENARIOS, MockAdapter, load_fixture_documents
from app.schemas.alert import Alert, AlertSource
from app.services.catalog import RulesCatalog

ROOT = Path(__file__).resolve().parent.parent


async def drain(adapter: MockAdapter) -> list[Alert]:
    alerts: list[Alert] = []
    while not adapter.exhausted:
        alerts.extend(await adapter.fetch_new_alerts())
    return alerts


@pytest.mark.asyncio
async def test_replay_fixtures_cover_catalog_and_correspond_to_vendor_logs() -> None:
    documents = load_fixture_documents(DEFAULT_FIXTURES)
    catalog = RulesCatalog.from_file(ROOT / "config" / "rules_catalog.yaml")
    raw_lines = {
        line
        for path in (ROOT / "fixtures" / "logs").glob("*.log")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    }
    adapter = MockAdapter(
        mode="replay",
        start_time=datetime(2026, 11, 2, 12, tzinfo=UTC),
        batch_size=20,
    )
    alerts = await drain(adapter)

    assert len(documents) == len(alerts) == 12
    assert {alert.rule.catalog_id for alert in alerts} == {
        entry.id for entry in catalog.entries
    }
    assert all(document["full_log"] in raw_lines for document in documents)
    assert {alert.device.vendor for alert in alerts} >= {
        "Netgate/pfSense",
        "OPNsense",
        "MikroTik",
        "Cisco",
        "Open vSwitch",
    }
    assert all(alert.source is AlertSource.MOCK for alert in alerts)


@pytest.mark.asyncio
async def test_ssh_bruteforce_scenario_is_a_failure_burst_then_success() -> None:
    adapter = MockAdapter(
        mode="scenario",
        scenario="ssh_bruteforce",
        duration_seconds=60,
        start_time=datetime(2026, 11, 2, 12, tzinfo=UTC),
        batch_size=50,
    )
    alerts = await drain(adapter)

    failures = [alert for alert in alerts if alert.rule.id == "100210"]
    assert len(alerts) == 31
    assert len(failures) == 30
    assert alerts[-1].rule.id == "100220"
    assert (failures[-1].timestamp - failures[0].timestamp).total_seconds() == 60
    assert len({alert.alert_id for alert in failures}) == 30
    assert len({alert.dedup_key for alert in failures}) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_every_named_scenario_produces_canonical_alerts(scenario: str) -> None:
    alerts = await drain(
        MockAdapter(
            mode="scenario",
            scenario=scenario,
            start_time=datetime(2026, 11, 2, 12, tzinfo=UTC),
            batch_size=100,
        )
    )

    assert alerts
    assert all(isinstance(alert, Alert) for alert in alerts)
    assert all(alert.rule.catalog_id for alert in alerts)


@pytest.mark.asyncio
async def test_random_mode_honors_severity_distribution_and_randomizes_entities() -> None:
    alerts = await drain(
        MockAdapter(
            mode="random",
            count=20,
            duration_seconds=3600,
            severity_distribution={"low": 1, "medium": 0, "high": 0, "critical": 0},
            seed=7,
            start_time=datetime(2026, 11, 2, 12, tzinfo=UTC),
            batch_size=50,
        )
    )

    assert len(alerts) == 20
    assert {alert.severity.value for alert in alerts} == {"low"}
    assert len({alert.device.name for alert in alerts}) > 1
    assert len({str(alert.network.src_ip) for alert in alerts}) > 1
    assert len({alert.timestamp for alert in alerts}) == 20


@pytest.mark.asyncio
async def test_replay_rate_is_applied_between_batches() -> None:
    waits: list[float] = []

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)
        await asyncio.sleep(0)

    adapter = MockAdapter(
        mode="replay",
        rate_per_second=4,
        batch_size=1,
        sleeper=fake_sleep,
    )
    await adapter.fetch_new_alerts()
    await adapter.fetch_new_alerts()

    assert waits == [0.25]
