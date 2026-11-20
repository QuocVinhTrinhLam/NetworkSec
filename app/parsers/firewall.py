"""Parser for verified pfSense IPv4 filterlog block records."""

from __future__ import annotations

import csv
import re
from datetime import datetime, tzinfo

from app.parsers.base import ParserAttempt, parse_timestamp_without_year
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)

PARSER_NAME = "pfsense_filterlog"
HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2}) (?P<hostname>[^\s]+) "
    r"filterlog\[(?P<pid>\d+)\]: (?P<payload>.+)$"
)


def _port(value: str) -> int | None:
    return int(value) if value else None


def parse_firewall(
    raw_message: str,
    *,
    received_at: datetime,
    source_timezone: tzinfo,
    source_host: str | None,
) -> ParserAttempt:
    """Parse pfSense IPv4 block records using the documented CSV field order."""
    _ = source_host
    if " filterlog[" not in raw_message:
        return ParserAttempt(recognized=False)
    header = HEADER.fullmatch(raw_message)
    if header is None:
        return ParserAttempt(True, PARSER_NAME, reason="invalid_filterlog_header", malformed=True)
    values = header.groupdict()
    if "pfsense" not in values["hostname"].lower():
        return ParserAttempt(True, PARSER_NAME, reason="unsupported_firewall_vendor")
    fields = next(csv.reader([values["payload"]], strict=True))
    if len(fields) < 20:
        return ParserAttempt(True, PARSER_NAME, reason="short_filterlog_record", malformed=True)
    action = fields[6].lower()
    if action != "block":
        return ParserAttempt(True, PARSER_NAME, reason="unsupported_filterlog_action")
    if fields[8] != "4":
        return ParserAttempt(True, PARSER_NAME, reason="unsupported_filterlog_ip_version")
    if len(fields) < 22:
        return ParserAttempt(True, PARSER_NAME, reason="missing_filterlog_ports", malformed=True)

    event = NormalizedEvent(
        timestamp=parse_timestamp_without_year(
            values["month"],
            values["day"],
            values["clock"],
            received_at,
            source_timezone,
        ),
        received_at=received_at,
        vendor=EventVendor.PFSENSE,
        product="pfSense",
        event_type=EventType.ACL_DENY,
        severity=EventSeverity.MEDIUM,
        outcome=EventOutcome.DENIED,
        device_name=values["hostname"],
        message=values["payload"],
        raw_message=raw_message,
        rule_id=fields[0],
        rule_tracker=fields[3] or None,
        interface_name=fields[4],
        source_ip=fields[18],
        destination_ip=fields[19],
        source_port=_port(fields[20]),
        destination_port=_port(fields[21]),
        protocol=fields[16].lower(),
        direction=fields[7].lower(),
        action=action,
        vendor_severity=action,
        parser_name=PARSER_NAME,
    )
    return ParserAttempt(True, PARSER_NAME, event=event)
