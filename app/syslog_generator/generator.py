"""Small, dependency-free Syslog sender used by the Phase 2 lab."""

from __future__ import annotations

import re
import socket
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

HEADER_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
DEFAULT_MAX_MESSAGE_BYTES = 32 * 1024


class Protocol(StrEnum):
    """Supported Syslog transports."""

    TCP = "tcp"
    UDP = "udp"


class SyslogSendError(RuntimeError):
    """Raised when a message cannot be sent after configured retries."""


@dataclass(frozen=True, slots=True)
class GeneratorConfig:
    """Transport and pacing settings for a generator run."""

    host: str = "127.0.0.1"
    port: int = 5514
    protocol: Protocol = Protocol.TCP
    rate: float = 10.0
    retries: int = 3
    retry_delay: float = 0.5
    connect_timeout: float = 3.0
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES

    def __post_init__(self) -> None:
        if not self.host or len(self.host) > 255:
            raise ValueError("host must contain 1 to 255 characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.rate < 0:
            raise ValueError("rate must be zero or greater")
        if self.retries < 0:
            raise ValueError("retries must be zero or greater")
        if self.retry_delay < 0 or self.connect_timeout <= 0:
            raise ValueError("retry_delay must be non-negative and connect_timeout positive")
        if not 1 <= self.max_message_bytes <= DEFAULT_MAX_MESSAGE_BYTES:
            raise ValueError(f"max_message_bytes must be between 1 and {DEFAULT_MAX_MESSAGE_BYTES}")


class EventPacer:
    """Apply a stable upper event rate without sleeping after the final event."""

    def __init__(
        self,
        rate: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.clock = clock
        self.sleep = sleep
        self.next_deadline: float | None = None

    def wait(self) -> None:
        """Wait until the next event slot; the first event is immediate."""
        now = self.clock()
        if self.next_deadline is None or self.interval == 0:
            self.next_deadline = now + self.interval
            return
        delay = self.next_deadline - now
        if delay > 0:
            self.sleep(delay)
            now = self.clock()
        self.next_deadline = max(self.next_deadline + self.interval, now + self.interval)


def _validate_header_token(value: str, field: str) -> str:
    if not HEADER_TOKEN.fullmatch(value):
        raise ValueError(f"{field} must contain only letters, digits, dot, underscore, or hyphen")
    return value


def build_rfc5424_event(
    sequence_id: int,
    *,
    timestamp: datetime | None = None,
    hostname: str = "networksec-generator",
    app_name: str = "syslog-generator",
    facility: int = 16,
    severity: int = 6,
) -> bytes:
    """Build one RFC 5424 test event with a searchable sequence identifier."""
    if sequence_id < 0:
        raise ValueError("sequence_id must be non-negative")
    if not 0 <= facility <= 23 or not 0 <= severity <= 7:
        raise ValueError("facility must be 0..23 and severity must be 0..7")
    _validate_header_token(hostname, "hostname")
    _validate_header_token(app_name, "app_name")
    event_time = timestamp or datetime.now(UTC)
    if event_time.tzinfo is None or event_time.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    utc_time = event_time.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    sequence = f"{sequence_id:08d}"
    priority = facility * 8 + severity
    message = (
        f"<{priority}>1 {utc_time} {hostname} {app_name} - NETWORKSEC "
        f'[networksec@32473 sequenceId="{sequence}"] '
        f"sequence_id={sequence} synthetic network event"
    )
    return message.encode("utf-8")


def iter_generated_events(
    count: int,
    *,
    start_sequence: int = 1,
    hostname: str = "networksec-generator",
    app_name: str = "syslog-generator",
) -> Iterator[bytes]:
    """Yield a deterministic number of RFC 5424 test messages."""
    if count < 1:
        raise ValueError("count must be at least 1")
    if start_sequence < 0:
        raise ValueError("start_sequence must be non-negative")
    for offset in range(count):
        yield build_rfc5424_event(
            start_sequence + offset,
            hostname=hostname,
            app_name=app_name,
        )


def iter_loghub_messages(path: Path, *, limit: int | None = None) -> Iterator[bytes]:
    """Replay non-empty line-oriented Loghub records without decoding their payload."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1 when provided")
    emitted = 0
    with path.open("rb") as source:
        for raw_line in source:
            message = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
            if message.endswith(b"\r"):
                message = message[:-1]
            if not message:
                continue
            yield message
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def _validate_payload(payload: bytes, max_message_bytes: int) -> None:
    if not payload:
        raise ValueError("Syslog payload must not be empty")
    if b"\n" in payload or b"\r" in payload:
        raise ValueError("Syslog payload must be a single record without CR/LF")
    if len(payload) > max_message_bytes:
        raise ValueError(f"Syslog payload exceeds the {max_message_bytes}-byte limit")


def _connect_tcp(config: GeneratorConfig) -> socket.socket:
    connection = socket.create_connection(
        (config.host, config.port),
        timeout=config.connect_timeout,
    )
    connection.settimeout(config.connect_timeout)
    return connection


def send_messages(
    messages: Iterable[bytes],
    config: GeneratorConfig,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Send messages with newline TCP framing or one UDP datagram per message."""
    pacer = EventPacer(config.rate, clock=clock, sleep=sleep)
    sent = 0
    tcp_socket: socket.socket | None = None
    udp_socket: socket.socket | None = None
    if config.protocol is Protocol.UDP:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(config.connect_timeout)

    try:
        for payload in messages:
            _validate_payload(payload, config.max_message_bytes)
            pacer.wait()
            last_error: OSError | None = None
            for attempt in range(config.retries + 1):
                try:
                    if config.protocol is Protocol.TCP:
                        if tcp_socket is None:
                            tcp_socket = _connect_tcp(config)
                        tcp_socket.sendall(payload + b"\n")
                    else:
                        assert udp_socket is not None
                        udp_socket.sendto(payload, (config.host, config.port))
                    sent += 1
                    break
                except OSError as error:
                    last_error = error
                    if tcp_socket is not None:
                        tcp_socket.close()
                        tcp_socket = None
                    if attempt < config.retries:
                        sleep(config.retry_delay)
            else:
                raise SyslogSendError(
                    f"failed to send event {sent + 1} after {config.retries + 1} attempts"
                ) from last_error
    finally:
        if tcp_socket is not None:
            tcp_socket.close()
        if udp_socket is not None:
            udp_socket.close()
    return sent
