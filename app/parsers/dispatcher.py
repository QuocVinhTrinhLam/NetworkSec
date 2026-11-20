"""Safe dispatcher for verified multi-vendor Syslog parsers."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo

from pydantic import ValidationError

from app.parsers.cisco_ios import parse_cisco_ios
from app.parsers.firewall import parse_firewall
from app.parsers.mikrotik import parse_mikrotik
from app.schemas.event import MAX_RAW_MESSAGE_BYTES, NormalizedEvent, ParseStatus


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Non-throwing parse outcome; raw input is retained for diagnostics/replay."""

    status: ParseStatus
    raw_message: str
    event: NormalizedEvent | None = None
    parser_name: str | None = None
    reason: str | None = None


def parse_syslog(
    raw_message: str,
    *,
    received_at: datetime | None = None,
    source_timezone: tzinfo = UTC,
    source_host: str | None = None,
) -> ParseResult:
    """Parse one raw record without raising for malformed or unknown payloads."""
    if not isinstance(raw_message, str):
        return ParseResult(ParseStatus.MALFORMED, "", reason="raw_message_must_be_text")
    if not raw_message:
        return ParseResult(ParseStatus.MALFORMED, raw_message, reason="empty_message")
    try:
        encoded_message = raw_message.encode("utf-8")
    except UnicodeEncodeError:
        return ParseResult(ParseStatus.MALFORMED, raw_message, reason="invalid_unicode")
    if len(encoded_message) > MAX_RAW_MESSAGE_BYTES:
        return ParseResult(ParseStatus.MALFORMED, raw_message, reason="message_too_large")
    if "\x00" in raw_message or "\n" in raw_message or "\r" in raw_message:
        return ParseResult(ParseStatus.MALFORMED, raw_message, reason="invalid_record_delimiter")

    observed = received_at or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        return ParseResult(
            ParseStatus.MALFORMED, raw_message, reason="received_at_requires_timezone"
        )
    try:
        source_offset = observed.replace(tzinfo=source_timezone).utcoffset()
    except (ValueError, OverflowError):
        source_offset = None
    if source_offset is None:
        return ParseResult(ParseStatus.MALFORMED, raw_message, reason="invalid_source_timezone")
    observed = observed.astimezone(UTC)

    for parser in (parse_cisco_ios, parse_mikrotik, parse_firewall):
        try:
            attempt = parser(
                raw_message,
                received_at=observed,
                source_timezone=source_timezone,
                source_host=source_host,
            )
        except (ValueError, TypeError, OverflowError, KeyError, csv.Error, ValidationError):
            return ParseResult(
                ParseStatus.MALFORMED,
                raw_message,
                parser_name=parser.__name__,
                reason="parser_validation_failed",
            )
        if not attempt.recognized:
            continue
        if attempt.event is not None:
            return ParseResult(
                ParseStatus.PARSED,
                raw_message,
                event=attempt.event,
                parser_name=attempt.parser_name,
            )
        return ParseResult(
            ParseStatus.MALFORMED if attempt.malformed else ParseStatus.UNKNOWN,
            raw_message,
            parser_name=attempt.parser_name,
            reason=attempt.reason,
        )
    return ParseResult(ParseStatus.UNKNOWN, raw_message, reason="unsupported_format")
