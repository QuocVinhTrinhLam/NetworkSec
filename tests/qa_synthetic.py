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
    peer: str | None = None,
    interface: str | None = None,
    router: int = 1,
) -> str:
    if router not in (1, 2):
        raise ValueError("synthetic RouterOS endpoint must be 1 or 2")
    host = R1 if router == 1 else R2
    local_id = f"192.0.2.{router}"
    local_address = f"198.51.100.{router}"
    peer = peer or ("192.0.2.2" if router == 1 else "192.0.2.1")
    interface = interface or ("ether3" if router == 1 else "ether4")
    return (
        f"{timestamp(second).isoformat()} {host} route,ospf,info qa-v2 "
        f"{{ version: 2 router-id: {local_id} }} area {{ {area} }} "
        f"interface {{ p2p {local_address}%{interface} }} "
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
