"""Non-alert application models and compatibility exports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.schemas.alert import Alert as Alert


def utc_now_iso() -> str:
    """Return a sortable UTC timestamp with second precision."""
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class AttackScenario:
    """A measured attack test used in the capstone report."""

    id: int | None
    technique: str
    tool: str
    expected_rule: str
    detected: bool
    detection_time_seconds: float | None
    notes: str
    tested_at: str = field(default_factory=utc_now_iso)
