"""Shared adapter-to-storage ingestion pipeline."""

from __future__ import annotations

from app.adapters.base import BaseAdapter
from app.db import Database


class IngestionPipeline:
    """Persist validated alerts returned by a configured source adapter."""

    def __init__(self, adapter: BaseAdapter, database: Database) -> None:
        self.adapter = adapter
        self.database = database

    async def run_once(self) -> int:
        """Fetch one batch and return the number of newly stored alerts."""
        alerts = await self.adapter.fetch_new_alerts()
        return sum(self.database.insert_alert(alert) for alert in alerts)
