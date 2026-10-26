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
from app.web.routes import create_router

LOGGER = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    current = settings or get_settings()
    weak_secrets = {
        "development-only-change-me",
        "replace-me",
        "replace-with-at-least-32-random-characters",
    }
    public_bind = current.bind_host.strip().lower() not in {"127.0.0.1", "localhost", "::1"}
    if (current.app_env.lower() == "production" or public_bind) and (
        len(current.session_secret) < 32
        or current.session_secret in weak_secrets
    ):
        raise RuntimeError(
            "Production or a public bind requires a unique SESSION_SECRET "
            "of at least 32 characters"
        )
    database = Database(current.database_path)
    database.initialize()
    configure_logging(current.log_level, json_logs=current.json_logs)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if current.alert_source == "wazuh":
            database.set_state("wazuh_health", "not-implemented")
            LOGGER.warning(
                "ALERT_SOURCE=wazuh is a Phase 2 stub; dashboard remains available without polling"
            )
        else:
            database.set_state("mock_health", "connected")
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
    app.include_router(create_router(database, current, templates))
    app.state.database = database
    app.state.settings = current
    return app


app = create_app()
