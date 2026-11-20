from datetime import UTC, datetime

import pytest

from app.adapters import MockAdapter
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
