"""Resilient, cursor-based polling of the Wazuh Indexer REST API."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.config import Settings
from app.db import Database
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.normalizer import normalize_alert

LOGGER = logging.getLogger(__name__)
CURSOR_KEY = "wazuh_cursor"


class WazuhClient:
    """Query OpenSearch through a single reusable HTTP client."""

    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        verify: bool | str = settings.wazuh_verify_tls
        if settings.wazuh_ca_file:
            verify = settings.wazuh_ca_file
        self.client = httpx.AsyncClient(
            base_url=settings.wazuh_indexer_url.rstrip("/"),
            auth=(settings.wazuh_username, settings.wazuh_password),
            verify=verify,
            timeout=httpx.Timeout(10.0),
            transport=transport,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch_alerts(
        self, cursor: list[str] | None
    ) -> tuple[list[dict[str, Any]], list[str] | None]:
        """Fetch ordered alerts and filter the overlap using timestamp plus document ID."""
        if cursor:
            start = cursor[0]
        else:
            start = (
                datetime.now(UTC) - timedelta(minutes=self.settings.wazuh_initial_lookback_minutes)
            ).isoformat(timespec="milliseconds")
        body = {
            "size": 500,
            "track_total_hits": False,
            "query": {"range": {"@timestamp": {"gte": start}}},
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        pattern = quote(self.settings.wazuh_index_pattern, safe="*-_")
        response = await self.client.post(f"/{pattern}/_search", json=body)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        documents: list[dict[str, Any]] = []
        latest = cursor
        for hit in hits:
            source = hit.get("_source", {})
            timestamp = str(source.get("@timestamp", ""))
            document_id = str(hit.get("_id", ""))
            key = [timestamp, document_id]
            if cursor and tuple(key) <= tuple(cursor):
                continue
            documents.append({**source, "_id": document_id})
            if latest is None or tuple(key) > tuple(latest):
                latest = key
        return documents, latest


class WazuhPoller:
    """Normalize and persist a single page without losing the durable cursor."""

    def __init__(
        self,
        client: WazuhClient,
        database: Database,
        mapper: SeverityMapper,
        catalog: RulesCatalog,
    ) -> None:
        self.client = client
        self.database = database
        self.mapper = mapper
        self.catalog = catalog

    async def run_once(self) -> int:
        raw_cursor = self.database.get_state(CURSOR_KEY)
        cursor = json.loads(raw_cursor) if raw_cursor else None
        documents, latest = await self.client.fetch_alerts(cursor)
        inserted = 0
        for document in documents:
            alert = normalize_alert(
                document,
                self.mapper,
                self.catalog,
                external_id=str(document.get("_id") or ""),
            )
            inserted += int(self.database.insert_alert(alert))
        if latest:
            self.database.set_state(CURSOR_KEY, json.dumps(latest))
        self.database.set_state("wazuh_health", "connected")
        self.database.set_state("wazuh_last_poll", datetime.now(UTC).isoformat(timespec="seconds"))
        if documents:
            self.database.set_state("last_alert_time", str(documents[-1].get("@timestamp", "")))
        return inserted
