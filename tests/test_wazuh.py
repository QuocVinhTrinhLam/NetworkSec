import json
from pathlib import Path

import httpx
import pytest

from app.config import Settings
from app.db import Database
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.wazuh import WazuhClient, WazuhPoller

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.asyncio
async def test_wazuh_poll_tracks_timestamp_and_id_cursor(tmp_path: Path) -> None:
    observed_body = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed_body.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_id": "wazuh-1",
                            "_source": {
                                "@timestamp": "2026-10-25T10:00:00.000Z",
                                "agent": {"name": "edge-pfsense"},
                                "rule": {
                                    "id": "100201",
                                    "level": 10,
                                    "description": "Port scan",
                                    "groups": ["port_scan"],
                                },
                                "data": {"srcip": "203.0.113.5"},
                                "full_log": "scan",
                            },
                        }
                    ]
                }
            },
        )

    settings = Settings(
        database_path=tmp_path / "wazuh.db",
        severity_config=ROOT / "config" / "severity.yaml",
        rules_catalog=ROOT / "config" / "rules_catalog.yaml",
        wazuh_username="admin",
        wazuh_password="secret",
    )
    database = Database(settings.database_path)
    database.initialize()
    client = WazuhClient(settings, httpx.MockTransport(handler))
    poller = WazuhPoller(
        client,
        database,
        SeverityMapper.from_file(settings.severity_config),
        RulesCatalog.from_file(settings.rules_catalog),
    )
    try:
        assert await poller.run_once() == 1
    finally:
        await client.close()

    assert "range" in observed_body["query"]
    assert json.loads(database.get_state("wazuh_cursor") or "null") == [
        "2026-10-25T10:00:00.000Z",
        "wazuh-1",
    ]
    stored = database.list_alerts(limit=1)
    assert len(stored) == 1
    assert stored[0]["use_case_id"] == "port-scan"
