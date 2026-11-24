"""Shared filters and safe presentation for operational endpoints."""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Literal
from uuid import UUID

from app.schemas.backend import Category, DeviceStatus
from app.schemas.event import EventSeverity, EventType, EventVendor

request_id: ContextVar[UUID | None] = ContextVar("request_id", default=None)

_SECRET = re.compile(
    r"""(?ix) (\b(?:password|passwd|secret|token|api[_-]?key|authorization|community)\b["']?
    \s*(?:[:=]\s*|\s+)) (?:bearer\s+[^\s,;]+|"[^"]*"|'[^']*'|[^\s,;]+)"""
)
_URL_CREDENTIALS = re.compile(r"(://)[^\s/@]+:[^\s/@]+@")
_PRIORITY = re.compile(r"^<([0-9]{1,3})>")


def redact(value: str) -> str:
    """Mask recognizable credentials in displayed and indexed messages."""
    return _URL_CREDENTIALS.sub(r"\1[REDACTED]@", _SECRET.sub(r"\1[REDACTED]", value))


def transport_address(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ip_address(ip_address(value).packed))
    except ValueError:
        return None


def syslog_priority(raw: str, payload: str) -> tuple[int | None, bool]:
    match = _PRIORITY.match(raw)
    if match and int(match[1]) <= 191:
        priority = int(match[1])
        return priority, raw == f"<{priority}>{payload}"
    return None, False


def device_status(
    enabled: bool, last_seen: datetime | None, interval: int | None, now: datetime
) -> DeviceStatus:
    if not enabled:
        return "disabled"
    if last_seen is None or interval is None:
        return "unknown"
    return "active" if now - last_seen <= timedelta(seconds=interval) else "stale"


@dataclass(frozen=True, slots=True)
class EventFilters:
    start: datetime
    end: datetime
    device_id: UUID | None = None
    device_name: str | None = None
    severity: EventSeverity | None = None
    category: Category | None = None
    event_type: EventType | None = None
    vendor: EventVendor | None = None
    search: str | None = None


Period = Literal["daily", "weekly", "monthly", "custom"]


def date_range(
    start: datetime | None, end: datetime | None, period: Period = "daily"
) -> tuple[datetime, datetime]:
    if period == "custom" and (start is None or end is None):
        raise ValueError("Custom period requires start and end")
    range_end = end or datetime.now(UTC)
    if any(value is not None and value.utcoffset() is None for value in (start, end)):
        raise ValueError("start and end must include a timezone")
    range_end = range_end.astimezone(UTC)
    days = {"daily": 1, "weekly": 7, "monthly": 30, "custom": 1}[period]
    try:
        range_start = start.astimezone(UTC) if start else range_end - timedelta(days=days)
    except OverflowError as exc:
        raise ValueError("Invalid time range") from exc
    if not timedelta(0) < range_end - range_start <= timedelta(days=90):
        raise ValueError("Time range must be positive and at most 90 days")
    return range_start, range_end
