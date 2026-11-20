"""Health command tests without starting external storage services."""

from __future__ import annotations

from pathlib import Path

from app.processor.healthcheck import main
from app.processor.state import ProcessorStateStore


def test_healthcheck_requires_fresh_healthy_state(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "state.db"
    monkeypatch.setenv("PROCESSOR_STATE_PATH", str(path))
    monkeypatch.setenv("PROCESSOR_HEALTH_MAX_AGE_SECONDS", "30")

    assert main() == 1
    state = ProcessorStateStore(path)
    state.initialize()
    assert main() == 1

    state.heartbeat()
    assert main() == 0

    state.mark_blocked("test failure")
    assert main() == 1
