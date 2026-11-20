"""Shared parser result types and timestamp helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo

from app.schemas.event import NormalizedEvent

MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@dataclass(frozen=True, slots=True)
class ParserAttempt:
    """Internal result from one vendor parser."""

    recognized: bool
    parser_name: str | None = None
    event: NormalizedEvent | None = None
    reason: str | None = None
    malformed: bool = False


def parse_timestamp_with_year(
    month: str,
    day: str,
    year: str,
    clock: str,
    source_timezone: tzinfo,
) -> datetime:
    """Parse vendor-local timestamps that include a year."""
    month_number = MONTHS[month.lower()]
    time_value = datetime.strptime(clock, "%H:%M:%S").time()
    local = datetime(
        int(year),
        month_number,
        int(day),
        time_value.hour,
        time_value.minute,
        time_value.second,
        time_value.microsecond,
        tzinfo=source_timezone,
    )
    return local.astimezone(UTC)


def parse_timestamp_without_year(
    month: str,
    day: str,
    clock: str,
    received_at: datetime,
    source_timezone: tzinfo,
) -> datetime:
    """Resolve an RFC 3164-style timestamp to the year nearest receipt time."""
    month_number = MONTHS[month.lower()]
    time_value = datetime.strptime(clock, "%H:%M:%S.%f" if "." in clock else "%H:%M:%S").time()
    local_received = received_at.astimezone(source_timezone)
    candidates = [
        datetime(
            year,
            month_number,
            int(day),
            time_value.hour,
            time_value.minute,
            time_value.second,
            time_value.microsecond,
            tzinfo=source_timezone,
        )
        for year in (local_received.year - 1, local_received.year, local_received.year + 1)
    ]
    nearest = min(candidates, key=lambda value: abs(value.astimezone(UTC) - received_at))
    return nearest.astimezone(UTC)
