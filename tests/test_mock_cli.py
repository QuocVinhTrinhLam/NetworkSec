from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.adapters.mock import MockAdapter
from app.db import Database
from app.mock import build_parser, run
from app.services.ingestion import IngestionPipeline

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.asyncio
async def test_adapter_normalize_store_pipeline_is_idempotent(tmp_path: Path) -> None:
    database = Database(tmp_path / "mock.db")
    database.initialize()
    observed_at = datetime(2026, 11, 2, 12, tzinfo=UTC)

    first = IngestionPipeline(
        MockAdapter(mode="replay", start_time=observed_at, batch_size=20),
        database,
    )
    second = IngestionPipeline(
        MockAdapter(mode="replay", start_time=observed_at, batch_size=20),
        database,
    )

    assert await first.run_once() == 12
    assert await second.run_once() == 0
    assert len(database.list_alerts(20)) == 12


@pytest.mark.asyncio
async def test_seed_command_populates_requested_seven_day_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "seed.db"
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("SEVERITY_CONFIG", str(ROOT / "config" / "severity_map.yaml"))
    monkeypatch.setenv("RULES_CATALOG", str(ROOT / "config" / "rules_catalog.yaml"))
    args = build_parser().parse_args(["--seed-days", "7", "--count", "14", "--seed", "3"])

    inserted = await run(args)
    rows = Database(database_path).list_alerts(20)
    timestamps = [datetime.fromisoformat(str(row["timestamp"])) for row in rows]

    assert inserted == 14
    assert len(rows) == 14
    assert (max(timestamps) - min(timestamps)).total_seconds() == pytest.approx(
        7 * 24 * 60 * 60, abs=1
    )
