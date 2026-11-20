"""Parser for verified MikroTik RouterOS login failure records."""

from __future__ import annotations

import re
from datetime import datetime, tzinfo

from app.parsers.base import ParserAttempt, parse_timestamp_with_year
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)

PARSER_NAME = "mikrotik_routeros"
HEADER = re.compile(
    r"^(?P<month>[a-z]{3})/(?P<day>\d{1,2})/(?P<year>\d{4}) "
    r"(?P<clock>\d{2}:\d{2}:\d{2}) (?P<topics>[A-Za-z0-9,._-]+) (?P<message>.+)$"
)
LOGIN_FAILURE = re.compile(
    r"^login failure for user (?P<username>[^\s]+) from "
    r"(?P<source_ip>[^\s]+) via (?P<method>[A-Za-z0-9._-]+)$"
)


def parse_mikrotik(
    raw_message: str,
    *,
    received_at: datetime,
    source_timezone: tzinfo,
    source_host: str | None,
) -> ParserAttempt:
    """Parse RouterOS login failures and reject partial lookalikes."""
    if not re.match(r"^[a-z]{3}/\d{1,2}/\d{4} ", raw_message):
        return ParserAttempt(recognized=False)
    header = HEADER.fullmatch(raw_message)
    if header is None:
        return ParserAttempt(True, PARSER_NAME, reason="invalid_mikrotik_header", malformed=True)
    values = header.groupdict()
    if not values["message"].startswith("login failure for user "):
        return ParserAttempt(True, PARSER_NAME, reason="unsupported_mikrotik_message")
    match = LOGIN_FAILURE.fullmatch(values["message"])
    if match is None:
        return ParserAttempt(True, PARSER_NAME, reason="invalid_login_failure", malformed=True)

    topics = values["topics"].lower().split(",")
    if "critical" in topics:
        severity = EventSeverity.CRITICAL
        vendor_severity = "critical"
    elif "warning" in topics:
        severity = EventSeverity.MEDIUM
        vendor_severity = "warning"
    else:
        severity = EventSeverity.HIGH
        vendor_severity = "error"
    event = NormalizedEvent(
        timestamp=parse_timestamp_with_year(
            values["month"],
            values["day"],
            values["year"],
            values["clock"],
            source_timezone,
        ),
        received_at=received_at,
        vendor=EventVendor.MIKROTIK,
        product="RouterOS",
        event_type=EventType.LOGIN_FAILURE,
        severity=severity,
        outcome=EventOutcome.FAILURE,
        device_name=source_host,
        message=values["message"],
        raw_message=raw_message,
        source_ip=match.group("source_ip"),
        username=match.group("username"),
        auth_method=match.group("method").lower(),
        action="login",
        vendor_severity=vendor_severity,
        parser_name=PARSER_NAME,
    )
    return ParserAttempt(True, PARSER_NAME, event=event)
