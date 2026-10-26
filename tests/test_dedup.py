from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.db import Database
from app.services.dedup import Deduplicator, SlidingWindowRateLimiter


def _alert(alert_id: str = "a-1") -> dict[str, str]:
    return {
        "id": alert_id,
        "rule_id": "100210",
        "source_ip": "203.0.113.5",
        "device_name": "core-router",
        "timestamp": "2026-10-25T10:00:00+00:00",
    }


def test_duplicates_merge_inside_window_and_restart_after_window(tmp_path: Path) -> None:
    database = Database(tmp_path / "dedup.db")
    database.initialize()
    dedup = Deduplicator(database, window_seconds=60)
    start = datetime(2026, 10, 25, 10, 0, tzinfo=UTC)

    first = dedup.register(_alert("a-1"), start)
    duplicate = dedup.register(_alert("a-2"), start + timedelta(seconds=30))
    retry = dedup.register(_alert("a-2"), start + timedelta(seconds=31))
    later = dedup.register(_alert("a-3"), start + timedelta(seconds=61))

    assert (first.action, first.count) == ("new", 1)
    assert (duplicate.action, duplicate.count) == ("update", 2)
    assert (retry.action, retry.count) == ("update", 2)
    assert (later.action, later.count) == ("new", 1)


def test_rate_limiter_returns_suppressed_count_when_window_reopens() -> None:
    limiter = SlidingWindowRateLimiter(maximum=2, window_seconds=10)
    assert limiter.consume(0).allowed
    assert limiter.consume(1).allowed
    assert not limiter.consume(2).allowed
    assert not limiter.consume(3).allowed
    reopened = limiter.consume(11)
    assert reopened.allowed
    assert reopened.suppressed_summary == 2


def test_dedup_uses_event_time_for_backlog_alerts(tmp_path: Path) -> None:
    database = Database(tmp_path / "event-time.db")
    database.initialize()
    dedup = Deduplicator(database, window_seconds=60)
    first = _alert("a-1")
    later = {**_alert("a-2"), "timestamp": "2026-10-25T10:02:00+00:00"}

    assert dedup.register(first).action == "new"
    assert dedup.register(later).action == "new"
