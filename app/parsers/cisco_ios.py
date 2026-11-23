"""Parser for Cisco IOS messages verified by repository fixtures."""

from __future__ import annotations

import re
from datetime import datetime, tzinfo

from app.parsers.base import ParserAttempt, parse_timestamp_without_year
from app.parsers.ospf import parse_ospf_state
from app.schemas.event import (
    EventOutcome,
    EventSeverity,
    EventType,
    EventVendor,
    NormalizedEvent,
)

PARSER_NAME = "cisco_ios"
HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?):\s+"
    r"%(?P<facility>[A-Z_]+)-(?P<level>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s+"
    r"(?P<message>.+)$"
)
LINK_STATE = re.compile(
    r"^Interface (?P<interface>[A-Za-z][A-Za-z0-9./:_-]*), changed state to "
    r"(?P<state>up|down)$"
)
CONFIG_CHANGE = re.compile(
    r"^Configured from (?P<origin>.+?) by (?P<username>[^\s]+) on "
    r"(?P<session>[^\s]+) \((?P<source_ip>[^)]+)\)$"
)
PORT_SECURITY = re.compile(
    r"^Security violation occurred, caused by MAC address "
    r"(?P<mac>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}) on port "
    r"(?P<interface>[A-Za-z][A-Za-z0-9./:_-]*)\.$"
)
OSPF_MNEMONIC = "%OSPF-5-ADJCHG:"
OSPF_HEADER_PREFIX = re.compile(r"^(?:<(?P<priority>[0-9]{1,3})>)?(?:[0-9]+:\s+)?\*?")
OSPF_ADJACENCY = re.compile(
    r"^Process [0-9]+, Nbr (?P<neighbor>[^\s,]+) on "
    r"(?P<interface>[A-Za-z][A-Za-z0-9./:_-]*) from "
    r"(?P<previous>[A-Za-z0-9-]+) to (?P<current>[A-Za-z0-9-]+),\s*\S.*$"
)


def _severity(level: int) -> EventSeverity:
    if level <= 2:
        return EventSeverity.CRITICAL
    if level == 3:
        return EventSeverity.HIGH
    if level == 4:
        return EventSeverity.MEDIUM
    return EventSeverity.LOW


def parse_cisco_ios(
    raw_message: str,
    *,
    received_at: datetime,
    source_timezone: tzinfo,
    source_host: str | None,
) -> ParserAttempt:
    """Parse supported Cisco IOS mnemonics without guessing unknown messages."""
    if not re.search(r"%[A-Z_]+-[0-7]-[A-Z0-9_]+:", raw_message):
        return ParserAttempt(recognized=False)
    header = HEADER.fullmatch(raw_message)
    if header is None and OSPF_MNEMONIC in raw_message:
        prefix = OSPF_HEADER_PREFIX.match(raw_message)
        if prefix and (prefix["priority"] is None or int(prefix["priority"]) <= 191):
            candidate = HEADER.fullmatch(raw_message[prefix.end() :])
            if candidate and (candidate["facility"], candidate["level"], candidate["mnemonic"]) == (
                "OSPF",
                "5",
                "ADJCHG",
            ):
                header = candidate
    if header is None:
        return ParserAttempt(True, PARSER_NAME, reason="invalid_cisco_header", malformed=True)

    values = header.groupdict()
    timestamp = parse_timestamp_without_year(
        values["month"],
        values["day"],
        values["clock"],
        received_at,
        source_timezone,
    )
    rule_id = f"{values['facility']}-{values['level']}-{values['mnemonic']}"
    level = int(values["level"])
    common = {
        "timestamp": timestamp,
        "received_at": received_at,
        "vendor": EventVendor.CISCO,
        "product": "IOS",
        "severity": _severity(level),
        "device_name": source_host,
        "message": values["message"],
        "raw_message": raw_message,
        "rule_id": rule_id,
        "vendor_severity": values["level"],
        "parser_name": PARSER_NAME,
    }

    if rule_id == "OSPF-5-ADJCHG":
        match = OSPF_ADJACENCY.fullmatch(values["message"])
        if match is None:
            return ParserAttempt(True, PARSER_NAME, reason="invalid_cisco_ospf", malformed=True)
        previous_state = parse_ospf_state(match["previous"])
        current_state = parse_ospf_state(match["current"])
        event_type, outcome = current_state.classification
        event = NormalizedEvent(
            **common,
            schema_version="1.1",
            event_type=event_type,
            outcome=outcome,
            interface_name=match["interface"],
            routing_protocol="ospf",
            neighbor_router_id=match["neighbor"],
            previous_state=previous_state,
            current_state=current_state,
        )
        return ParserAttempt(True, PARSER_NAME, event=event)

    if values["facility"] == "LINK" and values["mnemonic"] == "UPDOWN":
        match = LINK_STATE.fullmatch(values["message"])
        if match is None:
            return ParserAttempt(True, PARSER_NAME, reason="invalid_link_state", malformed=True)
        state = match.group("state")
        event = NormalizedEvent(
            **common,
            event_type=EventType.LINK_UP if state == "up" else EventType.LINK_DOWN,
            outcome=EventOutcome.SUCCESS if state == "up" else EventOutcome.FAILURE,
            interface_name=match.group("interface"),
            interface_state=state,
        )
        return ParserAttempt(True, PARSER_NAME, event=event)

    if values["facility"] == "SYS" and values["mnemonic"] == "CONFIG_I":
        match = CONFIG_CHANGE.fullmatch(values["message"])
        if match is None:
            return ParserAttempt(True, PARSER_NAME, reason="invalid_config_change", malformed=True)
        event = NormalizedEvent(
            **common,
            event_type=EventType.CONFIGURATION_CHANGE,
            outcome=EventOutcome.SUCCESS,
            username=match.group("username"),
            session=match.group("session"),
            source_ip=match.group("source_ip"),
            action="configured",
        )
        return ParserAttempt(True, PARSER_NAME, event=event)

    if values["facility"] == "PORT_SECURITY" and values["mnemonic"] == "PSECURE_VIOLATION":
        match = PORT_SECURITY.fullmatch(values["message"])
        if match is None:
            return ParserAttempt(True, PARSER_NAME, reason="invalid_port_security", malformed=True)
        event = NormalizedEvent(
            **common,
            event_type=EventType.PORT_SECURITY,
            outcome=EventOutcome.DENIED,
            interface_name=match.group("interface"),
            mac_address=match.group("mac").lower(),
            action="violation",
        )
        return ParserAttempt(True, PARSER_NAME, event=event)

    return ParserAttempt(True, PARSER_NAME, reason="unsupported_cisco_mnemonic")
