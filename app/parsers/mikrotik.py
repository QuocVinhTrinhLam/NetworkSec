"""Parser for MikroTik RouterOS login failures and OSPFv2 transitions."""

from __future__ import annotations

import re
from datetime import datetime, tzinfo
from ipaddress import IPv4Address

from app.parsers.base import ParserAttempt, parse_timestamp_with_year, parse_timestamp_without_year
from app.parsers.ospf import parse_ospf_state
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
REMOTE_HEADER = re.compile(
    r"^(?:<(?P<priority>[0-9]{1,3})>)?"
    r"(?:(?P<iso>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:?[0-9]{2}))|"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>[0-9]{1,2})\s+"
    r"(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2}))\s+"
    r"(?P<host>[A-Za-z0-9_.:-]+)\s+"
    r"(?:(?P<topics>[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)+)\s+)?(?P<message>.+)$"
)
OSPF_V2_INSTANCE = re.compile(r"^[A-Za-z0-9_.-]+\s+\{\s*version:\s+2\b")
OSPF_ADJACENCY = re.compile(
    r"^[A-Za-z0-9_.-]+\s+\{\s*version:\s+2\s+(?:vrf:\s+[0-9]+\s+)?"
    r"router-id:\s+(?P<local_id>[^\s{}]+)\s*\}\s+"
    r"[A-Za-z0-9_.-]+\s+\{\s*(?P<area>[^\s{}]+)\s*\}\s+"
    r"interface\s+\{\s*(?:instance-id:\s+[0-9]+\s+)?(?:p2p|p2p-unnumbered|broadcast)\s+"
    r"(?P<local_address>[0-9.]+)%(?P<interface>[A-Za-z0-9*][A-Za-z0-9*./:_-]*)\s*\}\s+"
    r"neighbor\s+\{\s*router-id:\s+(?P<neighbor_id>[^\s{}]+)\s+"
    r"state:\s+(?P<previous>[A-Za-z0-9-]+)\s*\}\s+"
    r"state change to\s+(?P<current>[A-Za-z0-9-]+)$"
)
OSPF_TOPIC_SEVERITIES = {
    "critical": EventSeverity.CRITICAL,
    "error": EventSeverity.HIGH,
    "warning": EventSeverity.MEDIUM,
    "info": EventSeverity.LOW,
    "debug": EventSeverity.LOW,
}


def parse_mikrotik(
    raw_message: str,
    *,
    received_at: datetime,
    source_timezone: tzinfo,
    source_host: str | None,
) -> ParserAttempt:
    """Parse console login failures and allowlisted RouterOS v7 neighbor transitions."""
    if not re.match(r"^[a-z]{3}/\d{1,2}/\d{4} ", raw_message):
        remote_header = REMOTE_HEADER.fullmatch(raw_message)
        if remote_header is None:
            return ParserAttempt(recognized=False)
        return _parse_ospf(raw_message, remote_header, received_at, source_timezone, source_host)
    header = HEADER.fullmatch(raw_message)
    if header is None:
        return ParserAttempt(True, PARSER_NAME, reason="invalid_mikrotik_header", malformed=True)
    values = header.groupdict()
    if not values["message"].startswith("login failure for user "):
        ospf = _parse_ospf(raw_message, header, received_at, source_timezone, source_host)
        if ospf.recognized:
            return ospf
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


def _parse_ospf(
    raw_message: str,
    header: re.Match[str],
    received_at: datetime,
    source_timezone: tzinfo,
    source_host: str | None,
) -> ParserAttempt:
    values = header.groupdict()
    message = values["message"]
    topics = values["topics"].lower().split(",") if values["topics"] else []
    if (
        (topics and "ospf" not in topics)
        or OSPF_V2_INSTANCE.match(message) is None
        or "neighbor {" not in message
        or "state change to" not in message
    ):
        return ParserAttempt(recognized=False)
    match = OSPF_ADJACENCY.fullmatch(message)
    if match is None or (values.get("priority") and int(values["priority"]) > 191):
        return ParserAttempt(True, PARSER_NAME, reason="invalid_mikrotik_ospf", malformed=True)
    IPv4Address(match["local_address"])

    if values.get("iso"):
        timestamp = datetime.fromisoformat(values["iso"])
    elif values.get("year"):
        timestamp = parse_timestamp_with_year(
            values["month"], values["day"], values["year"], values["clock"], source_timezone
        )
    else:
        timestamp = parse_timestamp_without_year(
            values["month"], values["day"], values["clock"], received_at, source_timezone
        )

    previous_state = parse_ospf_state(match["previous"])
    current_state = parse_ospf_state(match["current"])
    event_type, outcome = current_state.classification
    vendor_severity = next((topic for topic in OSPF_TOPIC_SEVERITIES if topic in topics), None)
    event = NormalizedEvent(
        schema_version="1.1",
        timestamp=timestamp,
        received_at=received_at,
        vendor=EventVendor.MIKROTIK,
        product="RouterOS",
        event_type=event_type,
        severity=OSPF_TOPIC_SEVERITIES[vendor_severity] if vendor_severity else EventSeverity.LOW,
        outcome=outcome,
        device_name=values.get("host") or source_host,
        message=message,
        raw_message=raw_message,
        interface_name=match["interface"],
        routing_protocol="ospf",
        ospf_area=match["area"],
        local_router_id=match["local_id"],
        neighbor_router_id=match["neighbor_id"],
        previous_state=previous_state,
        current_state=current_state,
        vendor_severity=vendor_severity,
        parser_name=PARSER_NAME,
    )
    return ParserAttempt(True, PARSER_NAME, event=event)
