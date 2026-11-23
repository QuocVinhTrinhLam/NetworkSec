"""Deterministic QA-only Syslog and spool datasets with documentation-range IPs."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

BASE = datetime(2026, 11, 23, 12, tzinfo=UTC)
R1 = "qa-r1"
R2 = "qa-r2"


def timestamp(second: float) -> datetime:
    return BASE + timedelta(seconds=second)


def ios(second: float, body: str) -> str:
    return f"Nov 23 {timestamp(second):%H:%M:%S.%f}: {body}"


def ios_ospf(second: float, previous: str, current: str) -> str:
    return ios(
        second,
        f"%OSPF-5-ADJCHG: Process 1, Nbr 192.0.2.1 on Gi0/1 from {previous} to {current}, QA",
    )


def routeros_ospf(
    second: float,
    previous: str,
    current: str,
    *,
    area: str = "0.0.0.0",
    peer: str = "192.0.2.2",
    interface: str = "ether3",
) -> str:
    return (
        f"{timestamp(second).isoformat()} {R1} route,ospf,info qa-v2 "
        f"{{ version: 2 router-id: 192.0.2.1 }} area {{ {area} }} "
        f"interface {{ p2p 198.51.100.1%{interface} }} "
        f"neighbor {{ router-id: {peer} state: {previous} }} state change to {current}"
    )


def link_line(sequence: int) -> tuple[datetime, str]:
    observed = timestamp(sequence / 1000)
    state = "down" if sequence % 2 else "up"
    return observed, ios(
        sequence / 1000, f"%LINK-3-UPDOWN: Interface Gi0/1, changed state to {state}"
    )


def spool_line(raw: str, observed: datetime, host: str = "qa-switch") -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "1.0",
                "received_at": observed.isoformat(),
                "source_host": host,
                "source_ip": "198.51.100.9",
                "raw_message": "<189>" + raw,
                "parse_message": raw,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
