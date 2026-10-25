"""Internal data models shared by ingestion, storage, dashboard and bot."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    """Return a sortable UTC timestamp with second precision."""
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class Alert:
    """Normalized, safe-to-store representation of a Wazuh alert."""

    id: str
    timestamp: str
    device_name: str
    device_type: str
    source_ip: str | None
    dest_ip: str | None
    user: str | None
    rule_id: str
    rule_description: str
    severity: str
    mitre_id: str | None
    mitre_name: str | None
    raw_log: str
    use_case_id: str | None = None
    recommended_response: str | None = None
    wazuh_level: int = 0
    groups: list[str] = field(default_factory=list)
    count: int = 1

    def as_record(self) -> dict[str, Any]:
        """Convert the dataclass to a SQLite-ready mapping."""
        record = asdict(self)
        record["groups"] = ",".join(self.groups)
        return record


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
