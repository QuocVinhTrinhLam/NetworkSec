"""Container health check for processor progress and retry state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.config import get_settings
from app.processor.state import ProcessorStateStore


def main() -> int:
    """Return nonzero for absent, blocked, or stale processor health."""
    settings = get_settings()
    snapshot = ProcessorStateStore(settings.processor_state_path).health()
    if snapshot is None or snapshot.status != "healthy":
        return 1
    maximum_age = timedelta(seconds=settings.processor_health_max_age_seconds)
    if datetime.now(UTC) - snapshot.heartbeat_at > maximum_age:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
