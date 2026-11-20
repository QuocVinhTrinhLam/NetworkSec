from __future__ import annotations

import os
import subprocess
import time
import uuid

import pytest

from app.syslog_generator import (
    GeneratorConfig,
    Protocol,
    build_rfc5424_event,
    send_messages,
)

pytestmark = [
    pytest.mark.syslog_integration,
    pytest.mark.skipif(
        os.getenv("RUN_SYSLOG_INTEGRATION") != "1",
        reason="set RUN_SYSLOG_INTEGRATION=1 with the Compose rsyslog service running",
    ),
]


def _read_raw_spool() -> str:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "rsyslog",
            "sh",
            "-c",
            "test -f /var/log/networksec/raw.log && cat /var/log/networksec/raw.log",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout if result.returncode == 0 else ""


def test_rsyslog_collects_tcp_and_udp_without_changing_raw_messages() -> None:
    suffix = uuid.uuid4().hex[:8]
    start = int(suffix, 16) % 90_000_000
    tcp_events = [
        build_rfc5424_event(start + offset, hostname=f"tcp-{suffix}") for offset in range(2)
    ]
    udp_events = [
        build_rfc5424_event(start + 100 + offset, hostname=f"udp-{suffix}") for offset in range(2)
    ]

    assert send_messages(
        tcp_events,
        GeneratorConfig(protocol=Protocol.TCP, rate=0),
    ) == len(tcp_events)
    assert send_messages(
        udp_events,
        GeneratorConfig(protocol=Protocol.UDP, rate=0),
    ) == len(udp_events)

    expected = [event.decode("utf-8") for event in tcp_events + udp_events]
    deadline = time.monotonic() + 10
    raw_spool = ""
    while time.monotonic() < deadline:
        raw_spool = _read_raw_spool()
        if all(message in raw_spool.splitlines() for message in expected):
            break
        time.sleep(0.2)

    assert all(message in raw_spool.splitlines() for message in expected)
