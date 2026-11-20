"""Loki HTTP adapter for normalized network events."""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import ValidationError

from app.schemas.event import NormalizedEvent
from app.storage.base import (
    EventPage,
    EventQuery,
    InvalidCursorError,
    StorageError,
    StorageUnavailableError,
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
        if response.status_code not in {200, 204}:
            raise StorageError(f"Loki push failed with HTTP {response.status_code}")

    async def query_events(self, query: EventQuery) -> EventPage:
        cursor_time, seen_ids = _decode_cursor(query.cursor)
        end_ns = _to_ns(query.end)
        if cursor_time is not None:
            end_ns = min(end_ns, cursor_time + 1)
        fetch_limit = min(5000, query.limit + len(seen_ids) + 1)
        params = {
            "query": _logql(query),
            "start": str(_to_ns(query.start)),
            "end": str(end_ns),
            "limit": str(fetch_limit),
            "direction": "backward",
        }
        response = await self._request("GET", "/loki/api/v1/query_range", params=params)
        if response.status_code != 200:
            raise StorageError(f"Loki query failed with HTTP {response.status_code}")
        try:
            document = response.json()
            if document.get("status") != "success":
                raise StorageError("Loki returned a non-success query status")
            streams = document["data"]["result"]
            candidates = _parse_streams(streams)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise StorageError("Loki returned an invalid query response") from exc

        filtered = [
            item
            for item in candidates
            if not (
                cursor_time is not None and item[0] == cursor_time and item[1].event_id in seen_ids
            )
        ]
        selected = filtered[: query.limit]
        has_more = len(filtered) > query.limit
        next_cursor = None
        if has_more and selected:
            boundary = selected[-1][0]
            boundary_ids = set(seen_ids) if cursor_time == boundary else set()
            boundary_ids.update(
                event.event_id for timestamp, event in selected if timestamp == boundary
            )
            next_cursor = _encode_cursor(boundary, boundary_ids)
        return EventPage(tuple(event for _, event in selected), next_cursor)

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
    )
    if any(value is not None for _, value in json_filters):
        expression += " | json"
        for name, value in json_filters:
            if value is not None:
                expression += f" | {name}={json.dumps(value)}"
    return expression


def _parse_streams(streams: Any) -> list[tuple[int, NormalizedEvent]]:
    if not isinstance(streams, list):
        raise ValueError("Loki result must be a list")
    parsed: list[tuple[int, NormalizedEvent]] = []
    for stream in streams:
        values = stream.get("values", []) if isinstance(stream, dict) else []
        for value in values:
            if not isinstance(value, list) or len(value) < 2:
                continue
            try:
                event = NormalizedEvent.model_validate_json(value[1])
                parsed.append((int(value[0]), event))
            except (ValidationError, ValueError, TypeError):
                continue
    parsed.sort(key=lambda item: (item[0], item[1].event_id), reverse=True)
    unique: dict[str, tuple[int, NormalizedEvent]] = {}
    for item in parsed:
        unique.setdefault(item[1].event_id, item)
    return list(unique.values())


def _to_ns(value: datetime) -> int:
    utc_value = value.astimezone(UTC)
    seconds = int(utc_value.timestamp())
    return seconds * 1_000_000_000 + utc_value.microsecond * 1000


def _encode_cursor(timestamp_ns: int, seen_ids: set[str]) -> str:
    value = json.dumps(
        {"timestamp_ns": timestamp_ns, "seen_ids": sorted(seen_ids)},
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> tuple[int | None, set[str]]:
    if cursor is None:
        return None, set()
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + padding))
        timestamp_ns = int(value["timestamp_ns"])
        seen_ids = {str(item) for item in value["seen_ids"]}
        if timestamp_ns < 0 or any(len(item) != 64 for item in seen_ids):
            raise ValueError
        return timestamp_ns, seen_ids
    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ) as exc:
        raise InvalidCursorError("invalid event pagination cursor") from exc
