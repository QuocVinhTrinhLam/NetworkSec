from datetime import UTC, datetime

import pytest

from app.adapters import MockAdapter, WazuhAdapter, build_adapter
from app.config import Settings
from app.schemas.alert import Alert, Device, Network, Rule


def _alert() -> Alert:
    return Alert(
        timestamp=datetime(2026, 11, 2, 7, 3, 11, tzinfo=UTC),
        source="mock",
        device=Device(name="core-router", type="router", vendor="MikroTik"),
        severity="critical",
        rule=Rule(id="100210", description="SSH brute-force", level=13),
        network=Network(src_ip="203.0.113.5", dst_ip="10.0.99.1", dst_port=22),
        raw_log="login failure",
    )


@pytest.mark.asyncio
async def test_mock_adapter_yields_each_batch_once() -> None:
    adapter = MockAdapter([_alert()])
    assert len(await adapter.fetch_new_alerts()) == 1
    assert await adapter.fetch_new_alerts() == []


@pytest.mark.asyncio
async def test_wazuh_adapter_fails_with_phase_two_guidance() -> None:
    with pytest.raises(NotImplementedError, match="Phase 2"):
        await WazuhAdapter().fetch_new_alerts()


def test_adapter_selection_is_explicit() -> None:
    assert isinstance(build_adapter(Settings(alert_source="mock")), MockAdapter)
    assert isinstance(build_adapter(Settings(alert_source="wazuh")), WazuhAdapter)
    with pytest.raises(ValueError, match="ALERT_SOURCE"):
        build_adapter(Settings(alert_source="invalid"))
