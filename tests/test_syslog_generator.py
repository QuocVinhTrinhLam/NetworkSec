from __future__ import annotations

import socket
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.syslog_generator.generator import (
    EventPacer,
    GeneratorConfig,
    Protocol,
    SyslogSendError,
    build_rfc5424_event,
    iter_generated_events,
    iter_loghub_messages,
    send_messages,
)


def test_generated_events_have_ordered_sequence_ids() -> None:
    events = list(iter_generated_events(3, start_sequence=41))

    assert b'sequenceId="00000041"' in events[0]
    assert b"sequence_id=00000042" in events[1]
    assert b"sequence_id=00000043" in events[2]


def test_rfc5424_event_is_utc_and_validates_header_tokens() -> None:
    event = build_rfc5424_event(
        7,
        timestamp=datetime(2026, 11, 19, 1, 2, 3, tzinfo=UTC),
        hostname="router-lab-01",
    )

    assert event.startswith(b"<134>1 2026-11-19T01:02:03.000Z router-lab-01 ")
    with pytest.raises(ValueError, match="hostname"):
        build_rfc5424_event(8, hostname="bad host")


def test_loghub_replay_preserves_message_bytes(tmp_path: Path) -> None:
    fixture = tmp_path / "loghub.log"
    fixture.write_bytes(b"first raw message\nsecond \\xff message\r\n\n")

    assert list(iter_loghub_messages(fixture)) == [
        b"first raw message",
        b"second \\xff message",
    ]
    assert list(iter_loghub_messages(fixture, limit=1)) == [b"first raw message"]


def test_tcp_sender_uses_newline_framing() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    received = bytearray()

    def collect() -> None:
        connection, _ = listener.accept()
        with connection:
            while received.count(b"\n") < 2:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                received.extend(chunk)

    thread = threading.Thread(target=collect, daemon=True)
    thread.start()
    try:
        port = int(listener.getsockname()[1])
        sent = send_messages(
            [b"tcp-one", b"tcp-two"],
            GeneratorConfig(port=port, protocol=Protocol.TCP, rate=0),
        )
        thread.join(timeout=3)
    finally:
        listener.close()

    assert sent == 2
    assert bytes(received) == b"tcp-one\ntcp-two\n"


def test_udp_sender_uses_one_datagram_per_event() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(3)
    port = int(listener.getsockname()[1])

    try:
        sent = send_messages(
            [b"udp-one", b"udp-two"],
            GeneratorConfig(port=port, protocol=Protocol.UDP, rate=0),
        )
        received = [listener.recvfrom(4096)[0], listener.recvfrom(4096)[0]]
    finally:
        listener.close()

    assert sent == 2
    assert received == [b"udp-one", b"udp-two"]


def test_event_pacer_applies_configured_rate() -> None:
    now = [0.0]
    sleeps: list[float] = []

    def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay

    pacer = EventPacer(4, clock=lambda: now[0], sleep=fake_sleep)
    pacer.wait()
    pacer.wait()
    pacer.wait()

    assert sleeps == [0.25, 0.25]


def test_sender_rejects_multiline_and_reports_connection_failure() -> None:
    with pytest.raises(ValueError, match="single record"):
        send_messages([b"line one\nline two"], GeneratorConfig(rate=0))

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    unavailable_port = int(probe.getsockname()[1])
    probe.close()
    with pytest.raises(SyslogSendError, match="after 1 attempts"):
        send_messages(
            [b"cannot-connect"],
            GeneratorConfig(port=unavailable_port, rate=0, retries=0, connect_timeout=0.1),
        )
