"""Restart-safe bridge from the rsyslog spool to normalized storage."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.parsers.dispatcher import parse_syslog
from app.processor.state import Checkpoint, FileIdentity, ProcessorStateStore
from app.schemas.event import MAX_RAW_MESSAGE_BYTES, ParseStatus
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter
from app.storage.base import LogStorage

LOGGER = logging.getLogger(__name__)
MAX_ENVELOPE_BYTES = 128 * 1024


class ProcessorEnvelope(BaseModel):
    """Versioned metadata envelope emitted by rsyslog as one JSON line."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    received_at: AwareDatetime
    source_host: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    raw_message: str = Field(min_length=1, max_length=MAX_RAW_MESSAGE_BYTES)
    parse_message: str = Field(min_length=1, max_length=MAX_RAW_MESSAGE_BYTES)

    @field_validator("received_at")
    @classmethod
    def normalize_received_at(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("source_host", "source_ip", mode="before")
    @classmethod
    def normalize_missing_source(cls, value: object) -> object:
        return None if value is None or value == "" or value == "-" else value


@dataclass(frozen=True, slots=True)
class SpoolRecord:
    """One complete newline-delimited record with its next durable position."""

    payload: bytes
    start_offset: int
    checkpoint: Checkpoint


class ProcessingWorker:
    """Continuously parse, correlate, persist, and checkpoint raw Syslog records."""

    def __init__(
        self,
        *,
        spool_path: Path,
        state: ProcessorStateStore,
        correlation: CorrelationEngine,
        logs: LogStorage,
        writer: StorageWriter,
        source_timezone: tzinfo,
        poll_interval_seconds: float = 0.25,
        retry_interval_seconds: float = 2.0,
    ) -> None:
        if poll_interval_seconds <= 0 or retry_interval_seconds <= 0:
            raise ValueError("processor intervals must be positive")
        self.spool_path = spool_path
        self.state = state
        self.correlation = correlation
        self.logs = logs
        self.writer = writer
        self.source_timezone = source_timezone
        self.poll_interval_seconds = poll_interval_seconds
        self.retry_interval_seconds = retry_interval_seconds

    async def process_once(self) -> bool:
        """Process one complete record; return false when the spool is currently idle."""
        record = self._read_next()
        if record is None:
            self.state.heartbeat()
            return False
        try:
            envelope = _decode_envelope(record.payload)
        except ValueError as exc:
            self.state.dead_letter(
                record.checkpoint,
                record.payload,
                str(exc),
                start_offset=record.start_offset,
            )
            return True

        parsed = parse_syslog(
            envelope.parse_message,
            received_at=envelope.received_at,
            source_timezone=self.source_timezone,
            source_host=envelope.source_host or envelope.source_ip,
        )
        if parsed.status is not ParseStatus.PARSED or parsed.event is None:
            reason = f"parse_{parsed.status.value}:{parsed.reason or 'unspecified'}"
            self.state.dead_letter(
                record.checkpoint,
                record.payload,
                reason,
                start_offset=record.start_offset,
            )
            return True

        try:
            correlation = await asyncio.to_thread(self.correlation.process, parsed.event)
            if correlation.matched and correlation.alert is not None:
                await self.writer.persist(parsed.event, correlation.alert)
            else:
                await self.logs.push_event(parsed.event)
        except Exception as exc:
            detail = f"{type(exc).__name__}: downstream processing failed"
            self.state.mark_blocked(detail)
            raise

        self.state.advance(
            record.checkpoint,
            event_id=parsed.event.event_id,
            start_offset=record.start_offset,
            envelope=record.payload,
        )
        return True

    async def run_forever(self, stop: asyncio.Event | None = None) -> None:
        """Retry the same uncheckpointed record until shutdown or downstream recovery."""
        stop_event = stop or asyncio.Event()
        while not stop_event.is_set():
            try:
                processed = await self.process_once()
                delay = 0.0 if processed else self.poll_interval_seconds
            except Exception:
                LOGGER.exception("processor record failed; checkpoint retained for retry")
                delay = self.retry_interval_seconds
            if delay:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=delay)
                except TimeoutError:
                    pass

    def _read_next(self) -> SpoolRecord | None:
        try:
            with self.spool_path.open("rb") as source:
                stat = os.fstat(source.fileno())
                identity = FileIdentity(device=int(stat.st_dev), inode=int(stat.st_ino))
                checkpoint = self.state.load_checkpoint(self.spool_path, identity, stat.st_size)
                source.seek(checkpoint.byte_offset)
                start_offset = checkpoint.byte_offset
                payload = source.readline(MAX_ENVELOPE_BYTES + 1)
                if not payload:
                    return None
                if len(payload) > MAX_ENVELOPE_BYTES:
                    if not payload.endswith(b"\n"):
                        _discard_through_newline(source)
                    next_offset = source.tell()
                    return SpoolRecord(
                        payload,
                        start_offset,
                        Checkpoint(checkpoint.source_path, identity, next_offset),
                    )
                if not payload.endswith(b"\n"):
                    return None
                return SpoolRecord(
                    payload,
                    start_offset,
                    Checkpoint(checkpoint.source_path, identity, source.tell()),
                )
        except FileNotFoundError:
            return None


def _decode_envelope(payload: bytes) -> ProcessorEnvelope:
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope_too_large")
    try:
        text = payload.removesuffix(b"\n").removesuffix(b"\r").decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("envelope_invalid_utf8") from exc
    try:
        document = json.loads(text)
        return ProcessorEnvelope.model_validate(document)
    except json.JSONDecodeError as exc:
        raise ValueError("envelope_invalid_json") from exc
    except ValidationError as exc:
        raise ValueError("envelope_schema_invalid") from exc


def _discard_through_newline(source: BinaryIO) -> None:
    """Bound memory while locating the end of a corrupt oversized record."""
    while True:
        chunk = source.read(64 * 1024)
        if not chunk:
            return
        newline = chunk.find(b"\n")
        if newline >= 0:
            source.seek(newline + 1 - len(chunk), os.SEEK_CUR)
            return
