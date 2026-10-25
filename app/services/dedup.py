"""Deterministic Telegram deduplication and global rate limiting."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.db import Database


@dataclass(frozen=True, slots=True)
class DedupDecision:
    action: str
    fingerprint: str
    count: int
    message_ids: dict[str, int]


class Deduplicator:
    """Merge alerts that share rule, source and device within a time window."""

    def __init__(self, database: Database, window_seconds: int) -> None:
        self.database = database
        self.window_seconds = max(1, window_seconds)

    @staticmethod
    def fingerprint(alert: dict[str, Any]) -> str:
        identity = "\x1f".join(
            (
                str(alert.get("rule_id") or ""),
                str(alert.get("source_ip") or ""),
                str(alert.get("device_name") or ""),
            )
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def register(self, alert: dict[str, Any], now: datetime | None = None) -> DedupDecision:
        observed_at = now or datetime.now(UTC)
        fingerprint = self.fingerprint(alert)
        existing = self.database.get_notification_group(fingerprint)
        if existing and str(existing["alert_id"]) == str(alert["id"]):
            return DedupDecision(
                "update",
                fingerprint,
                int(existing["alert_count"]),
                self.database.parse_message_ids(existing["message_ids_json"]),
            )
        if existing:
            window_start = datetime.fromisoformat(existing["window_started"])
            elapsed = (observed_at - window_start).total_seconds()
        else:
            elapsed = self.window_seconds + 1

        if not existing or elapsed > self.window_seconds:
            count = 1
            message_ids: dict[str, int] = {}
            action = "new"
            window_started = observed_at.isoformat(timespec="seconds")
        else:
            count = int(existing["alert_count"]) + 1
            message_ids = self.database.parse_message_ids(existing["message_ids_json"])
            action = "update"
            window_started = str(existing["window_started"])

        self.database.save_notification_group(
            fingerprint=fingerprint,
            alert_id=str(alert["id"]),
            window_started=window_started,
            last_seen=observed_at.isoformat(timespec="seconds"),
            alert_count=count,
            message_ids=message_ids,
        )
        return DedupDecision(action, fingerprint, count, message_ids)


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    suppressed_summary: int = 0


class SlidingWindowRateLimiter:
    """Limit outbound messages and report how many alerts were suppressed."""

    def __init__(self, maximum: int, window_seconds: int) -> None:
        self.maximum = max(1, maximum)
        self.window_seconds = max(1, window_seconds)
        self._sent: deque[float] = deque()
        self._suppressed = 0

    def consume(self, now: float) -> RateDecision:
        cutoff = now - self.window_seconds
        while self._sent and self._sent[0] <= cutoff:
            self._sent.popleft()
        if len(self._sent) >= self.maximum:
            self._suppressed += 1
            return RateDecision(False)
        summary = self._suppressed
        self._suppressed = 0
        self._sent.append(now)
        return RateDecision(True, summary)
