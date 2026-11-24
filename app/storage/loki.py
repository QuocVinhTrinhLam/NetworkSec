"""Loki HTTP adapter for normalized network events."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import ValidationError

from app.schemas.event import NormalizedEvent
from app.storage.base import (
    EventPage,
    EventQuery,
    InvalidCursorError,
    LogEntryTooFarBehindError,
    StorageError,
    StorageUnavailableError,
)

MAX_LOKI_ENTRIES = 5_000
MAX_PAGE_QUERIES = 24
EVENT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class _Cursor:
    timestamp_ns: int
    before_id: str | None = None
    seen_ids: frozenset[str] = frozenset()

    def includes(self, timestamp_ns: int, event_id: str) -> bool:
        if timestamp_ns != self.timestamp_ns:
            return timestamp_ns < self.timestamp_ns
        return event_id not in self.seen_ids and (
            self.before_id is None or event_id < self.before_id
        )


class LokiLogStorage:
    """Push and query JSON events through Loki's stable HTTP API."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._client = client

    async def push_event(self, event: NormalizedEvent) -> None:
        timestamp_ns = str(_to_ns(event.timestamp))
        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "network-events",
                        "schema_version": event.schema_version,
                        "vendor": event.vendor.value,
                        "event_type": event.event_type.value,
                        "severity": event.severity.value,
                    },
                    "values": [[timestamp_ns, event.model_dump_json()]],
                }
            ]
        }
        response = await self._request("POST", "/loki/api/v1/push", json=payload)
        if (
            response.status_code == 400
            and "entry too far behind, entry timestamp is:" in response.text
        ):
            raise LogEntryTooFarBehindError("Loki rejected a log entry outside its ordering window")
        if response.status_code not in {200, 204}:
            raise StorageError(f"Loki push failed with HTTP {response.status_code}")

    async def query_events(self, query: EventQuery) -> EventPage:
        cursor = _decode_cursor(query.cursor)
        start_ns, end_ns = _to_ns(query.start), _to_ns(query.end)
        if cursor is not None:
            if not start_ns <= cursor.timestamp_ns < end_ns:
                raise InvalidCursorError("event pagination cursor is outside the query range")
            # Loki excludes the end timestamp. Re-read the cursor's entire tie.
            end_ns = cursor.timestamp_ns + 1

        expression = _logql(query)
        fetch_limit = min(MAX_LOKI_ENTRIES, query.limit + 1)
        results: dict[str, tuple[int, NormalizedEvent]] = {}
        for _ in range(MAX_PAGE_QUERIES):
            count, oldest, candidates = await self._query_batch(
                expression, start_ns, end_ns, fetch_limit
            )
            eligible = [
                (at, event)
                for at, event in candidates
                if event.event_id not in results
                and (cursor is None or cursor.includes(at, event.event_id))
            ]
            has_more = len(results) + len(eligible) > query.limit
            if count < fetch_limit or oldest is None:
                results.update((event.event_id, (at, event)) for at, event in eligible)
                break

            # A full Loki response can cut through the oldest timestamp. Its tie
            # may contain IDs that sort ahead of the IDs we received.
            complete = [(at, event) for at, event in eligible if at > oldest]
            if has_more and len(results) + len(complete) >= query.limit:
                results.update((event.event_id, (at, event)) for at, event in complete)
                break
            if fetch_limit < MAX_LOKI_ENTRIES:
                fetch_limit = min(fetch_limit * 2, MAX_LOKI_ENTRIES)
                continue
            if oldest + 1 >= end_ns:
                raise StorageError(
                    "Loki pagination could not complete a timestamp at the entry limit"
                )
            results.update((event.event_id, (at, event)) for at, event in complete)
            end_ns = oldest + 1
        else:
            raise StorageError("Loki pagination exceeded its query limit")

        selected = list(results.values())[: query.limit]
        next_cursor = None
        if has_more and selected:
            boundary, event = selected[-1]
            legacy_ids = cursor.seen_ids if cursor and boundary == cursor.timestamp_ns else ()
            next_cursor = _encode_cursor(
                _Cursor(
                    boundary,
                    event.event_id,
                    frozenset(key for key in legacy_ids if key < event.event_id),
                )
            )
        return EventPage(tuple(event for _, event in selected), next_cursor)

    async def _query_batch(
        self, expression: str, start_ns: int, end_ns: int, limit: int
    ) -> tuple[int, int | None, list[tuple[int, NormalizedEvent]]]:
        params = {
            "query": expression,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": "backward",
        }
        response = await self._request("GET", "/loki/api/v1/query_range", params=params)
        if response.status_code != 200:
            raise StorageError(f"Loki query failed with HTTP {response.status_code}")
        try:
            document = response.json()
            if not isinstance(document, dict) or not isinstance(document.get("status"), str):
                raise ValueError
            if document["status"] != "success":
                raise StorageError("Loki returned a non-success query status")
            data = document.get("data")
            if not isinstance(data, dict) or data.get("resultType", "streams") != "streams":
                raise ValueError
            return _parse_streams(data.get("result"))
        except (ValueError, RecursionError):
            raise StorageError("Loki returned an invalid query response") from None

    async def ready(self) -> bool:
        try:
            response = await self._request("GET", "/ready")
            return response.status_code == 200
        except StorageUnavailableError:
            return False

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            if self._client is not None:
                return await self._client.request(method, f"{self.base_url}{path}", **kwargs)
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                return await client.request(method, f"{self.base_url}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise StorageUnavailableError("Loki is unavailable") from exc


def _logql(query: EventQuery) -> str:
    labels = ['job="network-events"']
    for name, value in (
        ("schema_version", query.schema_version),
        ("severity", query.severity.value if query.severity else None),
        ("event_type", query.event_type.value if query.event_type else None),
        ("vendor", query.vendor.value if query.vendor else None),
    ):
        if value is not None:
            labels.append(f"{name}={json.dumps(value)}")
    expression = "{" + ",".join(labels) + "}"
    json_filters = (
        ("device_name", query.device_name),
        ("interface_name", query.interface_name),
        ("event_id", query.event_id),
    )
    if any(value is not None for _, value in json_filters):
        expression += " | json"
        for name, value in json_filters:
            if value is not None:
                expression += f" | {name}={json.dumps(value)}"
    return expression


def _parse_streams(streams: Any) -> tuple[int, int | None, list[tuple[int, NormalizedEvent]]]:
    if not isinstance(streams, list):
        raise ValueError("Loki result must be a list")
    count = 0
    oldest: int | None = None
    unique: dict[str, tuple[int, NormalizedEvent]] = {}
    for stream in streams:
        if not isinstance(stream, dict) or not isinstance(stream.get("stream", {}), dict):
            raise ValueError("invalid Loki log stream")
        values = stream.get("values")
        if not isinstance(values, list):
            raise ValueError("Loki log stream values must be a list")
        for value in values:
            if (
                not isinstance(value, list)
                or len(value) < 2
                or not all(isinstance(part, str) for part in value[:2])
            ):
                raise ValueError("invalid Loki log entry")
            timestamp = int(value[0])
            count += 1
            oldest = timestamp if oldest is None else min(oldest, timestamp)
            try:
                event = NormalizedEvent.model_validate_json(value[1])
            except (ValidationError, ValueError, TypeError):
                continue
            previous = unique.get(event.event_id)
            if (
                previous is None
                or timestamp > previous[0]
                or (timestamp == previous[0] and event.received_at < previous[1].received_at)
            ):
                unique[event.event_id] = timestamp, event
    ordered = sorted(unique.values(), key=lambda item: (item[0], item[1].event_id), reverse=True)
    return count, oldest, ordered


def _to_ns(value: datetime) -> int:
    utc_value = value.astimezone(UTC)
    seconds = int(utc_value.timestamp())
    return seconds * 1_000_000_000 + utc_value.microsecond * 1000


def _encode_cursor(cursor: _Cursor) -> str:
    payload: dict[str, int | str | None] = {
        "timestamp_ns": cursor.timestamp_ns,
        "before_id": cursor.before_id,
    }
    if cursor.seen_ids:
        # Legacy cursors can have holes in their tie ordering. Carry just those
        # old IDs, without growing the token as more pages are returned.
        payload["seen_ids"] = "".join(sorted(cursor.seen_ids))
    value = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> _Cursor | None:
    if cursor is None:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.b64decode(cursor + padding, altchars=b"-_", validate=True))
        timestamp_ns = value["timestamp_ns"]
        if type(timestamp_ns) is not int or not 0 <= timestamp_ns < 2**63:
            raise ValueError
        if "before_id" not in value:
            seen = value["seen_ids"]
            if (
                not isinstance(seen, list)
                or not seen
                or not all(isinstance(key, str) and EVENT_ID_PATTERN.fullmatch(key) for key in seen)
            ):
                raise ValueError
            return _Cursor(timestamp_ns, seen_ids=frozenset(seen))

        before_id = value["before_id"]
        seen = value.get("seen_ids", "")
        if (
            not isinstance(before_id, str)
            or not EVENT_ID_PATTERN.fullmatch(before_id)
            or not isinstance(seen, str)
            or len(seen) % 64
            or (seen and not re.fullmatch(r"[0-9a-f]+", seen))
        ):
            raise ValueError
        return _Cursor(
            timestamp_ns,
            before_id,
            frozenset(seen[index : index + 64] for index in range(0, len(seen), 64)),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidCursorError("invalid event pagination cursor") from exc
