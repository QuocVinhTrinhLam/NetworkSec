"""Transactional checkpoint, health, and dead-letter state for the processor."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import batched
from pathlib import Path

PROCESSOR_STATE_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS processor_checkpoints (
    source_path TEXT PRIMARY KEY,
    file_device INTEGER NOT NULL,
    file_inode INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL CHECK(byte_offset >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processor_dead_letters (
    dead_letter_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    file_device INTEGER NOT NULL,
    file_inode INTEGER NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    reason TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    record BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processor_dead_letters_source
    ON processor_dead_letters(source_path, file_device, file_inode, start_offset);

CREATE TABLE IF NOT EXISTS processor_event_receipts (
    event_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    file_device INTEGER NOT NULL,
    file_inode INTEGER NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processor_event_receipts_source
    ON processor_event_receipts(source_path, file_device, file_inode, start_offset);

CREATE TABLE IF NOT EXISTS processor_health (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    status TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    last_success_at TEXT,
    detail TEXT,
    processed_count INTEGER NOT NULL DEFAULT 0,
    dead_letter_count INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable identity of an open spool file."""

    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """Durable byte position for one source file."""

    source_path: str
    identity: FileIdentity
    byte_offset: int


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Processor liveness and progress counters."""

    status: str
    heartbeat_at: datetime
    last_success_at: datetime | None
    detail: str | None
    processed_count: int
    dead_letter_count: int


class ProcessorStateStore:
    """Keep progress atomic without coupling local state to external storage."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(PROCESSOR_STATE_SCHEMA)
            now = _now()
            connection.execute(
                """
                INSERT INTO processor_health(singleton, status, heartbeat_at)
                VALUES (1, 'starting', ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    status = 'starting', heartbeat_at = excluded.heartbeat_at, detail = NULL
                WHERE processor_health.status <> 'blocked'
                """,
                (now,),
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def load_checkpoint(
        self, source_path: Path, identity: FileIdentity, file_size: int
    ) -> Checkpoint:
        """Return a usable checkpoint, resetting safely after replacement/truncation."""
        canonical = str(source_path.resolve())
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM processor_checkpoints WHERE source_path = ?", (canonical,)
            ).fetchone()
        offset = 0
        if (
            row is not None
            and int(row["file_device"]) == identity.device
            and int(row["file_inode"]) == identity.inode
            and int(row["byte_offset"]) <= file_size
        ):
            offset = int(row["byte_offset"])
        return Checkpoint(canonical, identity, offset)

    def advance(
        self,
        checkpoint: Checkpoint,
        *,
        event_id: str,
        start_offset: int,
        envelope: bytes,
    ) -> None:
        """Record raw trace coordinates and advance after downstream success."""
        now = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO processor_event_receipts(
                    event_id, source_path, file_device, file_inode, start_offset,
                    end_offset, envelope_sha256, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event_id,
                    checkpoint.source_path,
                    checkpoint.identity.device,
                    checkpoint.identity.inode,
                    start_offset,
                    checkpoint.byte_offset,
                    hashlib.sha256(envelope).hexdigest(),
                    now,
                ),
            )
            self._upsert_checkpoint(connection, checkpoint, now)
            connection.execute(
                """
                UPDATE processor_health SET
                    status = 'healthy', heartbeat_at = ?, last_success_at = ?, detail = NULL,
                    processed_count = processed_count + 1
                WHERE singleton = 1
                """,
                (now, now),
            )

    def has_event_receipts(self, event_ids: Iterable[str]) -> bool:
        """Check that processing completed for each event referenced by a projection."""
        with self.connect() as connection:
            for batch in batched(set(event_ids), 500):
                placeholders = ", ".join("?" for _ in batch)
                count = connection.execute(
                    "SELECT COUNT(*) FROM processor_event_receipts "
                    f"WHERE event_id IN ({placeholders})",
                    batch,
                ).fetchone()[0]
                if count != len(batch):
                    return False
        return True

    def dead_letter(
        self, checkpoint: Checkpoint, record: bytes, reason: str, *, start_offset: int
    ) -> None:
        """Persist an invalid record and advance its checkpoint in one transaction."""
        if len(reason) > 255:
            reason = reason[:255]
        digest = hashlib.sha256(record).hexdigest()
        identity = "\x1f".join(
            (
                checkpoint.source_path,
                str(checkpoint.identity.device),
                str(checkpoint.identity.inode),
                str(start_offset),
                digest,
            )
        )
        dead_letter_id = hashlib.sha256(identity.encode()).hexdigest()
        now = _now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT INTO processor_dead_letters(
                    dead_letter_id, source_path, file_device, file_inode,
                    start_offset, end_offset, reason, record_sha256, record, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dead_letter_id) DO NOTHING
                """,
                (
                    dead_letter_id,
                    checkpoint.source_path,
                    checkpoint.identity.device,
                    checkpoint.identity.inode,
                    start_offset,
                    checkpoint.byte_offset,
                    reason,
                    digest,
                    record,
                    now,
                ),
            )
            self._upsert_checkpoint(connection, checkpoint, now)
            connection.execute(
                """
                UPDATE processor_health SET
                    status = 'healthy', heartbeat_at = ?, last_success_at = ?, detail = NULL,
                    dead_letter_count = dead_letter_count + ?
                WHERE singleton = 1
                """,
                (now, now, 1 if cursor.rowcount else 0),
            )

    def heartbeat(self, *, recovered_from: str | None = None) -> None:
        """Refresh idle health or clear a specific block after recovery."""
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE processor_health SET status = 'healthy', heartbeat_at = ?, detail = NULL
                WHERE singleton = 1 AND (status <> 'blocked' OR detail = ?)
                """,
                (_now(), recovered_from),
            )

    def mark_blocked(self, detail: str, *, preserve_existing: bool = False) -> None:
        """Expose a retryable processing failure without leaking record content."""
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE processor_health SET status = 'blocked', heartbeat_at = ?, detail = ?
                WHERE singleton = 1 AND (NOT ? OR status <> 'blocked')
                """,
                (_now(), detail[:255], preserve_existing),
            )

    def health(self) -> HealthSnapshot | None:
        """Read the current health row."""
        if not self.path.exists():
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM processor_health WHERE singleton = 1"
            ).fetchone()
        if row is None:
            return None
        return HealthSnapshot(
            status=str(row["status"]),
            heartbeat_at=_parse_time(row["heartbeat_at"]),
            last_success_at=(
                _parse_time(row["last_success_at"]) if row["last_success_at"] else None
            ),
            detail=str(row["detail"]) if row["detail"] else None,
            processed_count=int(row["processed_count"]),
            dead_letter_count=int(row["dead_letter_count"]),
        )

    @staticmethod
    def _upsert_checkpoint(
        connection: sqlite3.Connection, checkpoint: Checkpoint, now: str
    ) -> None:
        connection.execute(
            """
            INSERT INTO processor_checkpoints(
                source_path, file_device, file_inode, byte_offset, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source_path) DO UPDATE SET
                file_device = excluded.file_device,
                file_inode = excluded.file_inode,
                byte_offset = excluded.byte_offset,
                updated_at = excluded.updated_at
            """,
            (
                checkpoint.source_path,
                checkpoint.identity.device,
                checkpoint.identity.inode,
                checkpoint.byte_offset,
                now,
            ),
        )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("processor health timestamp must be timezone-aware")
    return parsed.astimezone(UTC)
