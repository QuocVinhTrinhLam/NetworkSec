"""FastAPI dashboard process."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import BASE_DIR, Settings, get_settings
from app.db import Database
from app.logging_config import configure_logging
from app.services.storage import StorageWriter
from app.storage.base import AlertStateStorage, LogStorage
from app.storage.loki import LokiLogStorage
from app.storage.postgres import PostgresAlertStorage
from app.storage.unavailable import UnavailableAlertStorage
from app.web.api import create_api_router
from app.web.routes import create_router

LOGGER = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    log_storage: LogStorage | None = None,
    alert_storage: AlertStateStorage | None = None,
) -> FastAPI:
    current = settings or get_settings()
    if not current.session_secret:
        raise RuntimeError("SESSION_SECRET is required")
    weak_secrets = {
        "development-only-change-me",
        "replace-me",
        "replace-with-at-least-32-random-characters",
    }
    public_bind = current.bind_host.strip().lower() not in {"127.0.0.1", "localhost", "::1"}
    if (current.app_env.lower() == "production" or public_bind) and (
        len(current.session_secret) < 32 or current.session_secret in weak_secrets
    ):
        raise RuntimeError(
            "Production or a public bind requires a unique SESSION_SECRET of at least 32 characters"
        )
    database = Database(current.database_path)
    database.initialize()
    logs = log_storage or LokiLogStorage(
        current.loki_url,
        timeout_seconds=current.loki_timeout_seconds,
    )
    alert_states = alert_storage or (
        PostgresAlertStorage(
            current.postgres_dsn,
            current.postgres_migrations_path,
            connect_timeout=current.postgres_connect_timeout_seconds,
        )
        if current.postgres_dsn
        else UnavailableAlertStorage()
    )
    configure_logging(current.log_level, json_logs=current.json_logs)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        alert_states.migrate()
        database.set_state("event_source_health", "connected")
        yield

    app = FastAPI(title=current.app_name, lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=current.session_secret,
        https_only=current.session_https_only,
        same_site="lax",
        max_age=8 * 60 * 60,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    templates = Jinja2Templates(directory=BASE_DIR / "app" / "templates")
    app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")
    app.include_router(create_router(database, current, templates, logs, alert_states))
    app.include_router(create_api_router(logs, alert_states))
    app.state.database = database
    app.state.log_storage = logs
    app.state.alert_storage = alert_states
    app.state.storage_writer = StorageWriter(logs, alert_states)
    app.state.settings = current
    return app


app = create_app()
