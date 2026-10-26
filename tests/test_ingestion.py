from pathlib import Path

import pytest

from app.adapters.mock import MockAdapter
from app.db import Database
from app.schemas.alert import Alert
from app.services.ingestion import IngestionPipeline


@pytest.mark.asyncio
async def test_pipeline_persists_validated_alert_once(tmp_path: Path) -> None:
    alert = Alert.model_validate(
        {
            "timestamp": "2026-10-25T10:00:00Z",
            "source": "mock",
            "device": {"name": "core-router", "type": "router"},
            "severity": "high",
            "rule": {"id": "100210", "description": "SSH brute force", "level": 10},
            "network": {"src_ip": "203.0.113.5", "dst_port": 22},
            "raw_log": "authentication failed",
        }
    )
    database = Database(tmp_path / "pipeline.db")
    database.initialize()
    pipeline = IngestionPipeline(MockAdapter([alert, alert]), database)

    assert await pipeline.run_once() == 1
    assert len(database.list_alerts()) == 1
    assert await pipeline.run_once() == 0
