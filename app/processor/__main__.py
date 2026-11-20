"""Production entry point for the persistent processing worker."""

from __future__ import annotations

import asyncio
import logging
import signal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from app.config import get_settings
from app.logging_config import configure_logging
from app.processor.state import ProcessorStateStore
from app.processor.worker import ProcessingWorker
from app.services.correlation import CorrelationEngine
from app.services.storage import StorageWriter
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage

LOGGER = logging.getLogger(__name__)


async def _run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, json_logs=settings.json_logs)
    if not settings.postgres_dsn:
        raise RuntimeError("POSTGRES_DSN is required by the processing worker")
    try:
        source_timezone = ZoneInfo(settings.processor_source_timezone)
    except ZoneInfoNotFoundError as exc:
        raise RuntimeError("PROCESSOR_SOURCE_TIMEZONE is invalid") from exc

    state = ProcessorStateStore(settings.processor_state_path)
    state.initialize()
    correlation = CorrelationEngine.from_files(
        settings.correlation_database_path,
        settings.correlation_rules_path,
    )
    alerts = PostgresAlertStorage(
        settings.postgres_dsn,
        settings.postgres_migrations_path,
        connect_timeout=settings.postgres_connect_timeout_seconds,
    )
    alerts.migrate()
    async with httpx.AsyncClient(timeout=settings.loki_timeout_seconds) as client:
        logs = LokiLogStorage(
            settings.loki_url,
            timeout_seconds=settings.loki_timeout_seconds,
            client=client,
        )
        if not await logs.ready() or not await asyncio.to_thread(alerts.ready):
            raise RuntimeError("processor storage dependencies are not ready")

        worker = ProcessingWorker(
            spool_path=settings.processor_spool_path,
            state=state,
            correlation=correlation,
            logs=logs,
            writer=StorageWriter(logs, alerts),
            source_timezone=source_timezone,
            poll_interval_seconds=settings.processor_poll_interval_seconds,
            retry_interval_seconds=settings.processor_retry_interval_seconds,
        )
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for name in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(name, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        LOGGER.info("processor started")
        await worker.run_forever(stop)
        LOGGER.info("processor stopped")


def main() -> None:
    """Run the worker until SIGINT or SIGTERM."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
