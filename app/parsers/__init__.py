"""Verified multi-vendor Syslog parsers."""

from app.parsers.dispatcher import ParseResult, parse_syslog

__all__ = ["ParseResult", "parse_syslog"]
