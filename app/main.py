"""Headless NetworkSec operational API."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.logging_config import configure_logging
from app.services.backend import request_id
from app.services.correlation import load_correlation_config
from app.services.topology import load_topology
from app.storage.backend import DuplicateResource, PostgresBackendStorage
from app.storage.base import AlertStateStorage, LogStorage, StorageError, StorageUnavailableError
from app.storage.loki import LokiLogStorage
from app.storage.managed_rules import RuleConflict
from app.storage.unavailable import UnavailableAlertStorage
from app.web.accounts import ApiAccounts, LoginThrottle
from app.web.api import create_api_router
from app.web.backend import create_backend_router
from app.web.body_limit import BodyLimitMiddleware


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
    production = current.app_env.lower() == "production" or public_bind
    if production and (not current.trusted_hosts or "*" in current.trusted_hosts):
        raise RuntimeError("Production or a public bind requires trusted hosts")
    if (public_bind or (production and current.app_url.startswith("https://"))) and (
        not current.session_https_only
    ):
        raise RuntimeError("Public binds and HTTPS require SESSION_HTTPS_ONLY for HSTS")
    if not 300 <= current.api_session_seconds <= 28800:
        raise RuntimeError("API_SESSION_SECONDS must be between 300 and 28800")
    for origin in current.frontend_origins:
        url = urlsplit(origin)
        if (
            url.scheme not in ("https", "http")
            or not url.hostname
            or url.username is not None
            or url.path
            or url.query
            or url.fragment
            or "*" in origin
            or (
                production
                and url.scheme != "https"
                and url.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise RuntimeError("FRONTEND_ORIGINS must contain explicit origins")
    logs = log_storage or LokiLogStorage(
        current.loki_url,
        timeout_seconds=current.loki_timeout_seconds,
    )
    backend = (
        PostgresBackendStorage(
            current.postgres_dsn,
            current.postgres_migrations_path,
            connect_timeout=current.postgres_connect_timeout_seconds,
        )
        if current.postgres_dsn
        else None
    )
    alert_states = alert_storage or backend or UnavailableAlertStorage()
    configure_logging(current.log_level, json_logs=current.json_logs)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        alert_states.migrate()
        if backend is not None and alert_states is not backend:
            backend.migrate()
        yield

    app = FastAPI(
        title=current.app_name,
        lifespan=lifespan,
        openapi_url=None if production else "/openapi.json",
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(BodyLimitMiddleware)
    if production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(current.trusted_hosts))
    if current.frontend_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(current.frontend_origins),
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            expose_headers=[
                "X-Request-ID",
                "Retry-After",
                "Content-Disposition",
                "X-Report-Truncated",
            ],
        )

    @app.exception_handler(StorageError)
    async def storage_error(_request: Request, exc: StorageError) -> JSONResponse:
        if isinstance(exc, (DuplicateResource, RuleConflict)):
            return JSONResponse(status_code=409, content={"detail": str(exc)})
        if isinstance(exc, StorageUnavailableError):
            return JSONResponse(status_code=503, content={"detail": "Storage is unavailable"})
        return JSONResponse(status_code=502, content={"detail": "Storage operation failed"})

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Validation input and context can contain credentials, including in nested bodies.
        detail = [
            {
                "loc": (
                    (*error["loc"][:-1], "unknown_field")
                    if error["type"] == "extra_forbidden"
                    and request.url.path.startswith(("/api/v1/auth/", "/api/v1/users"))
                    else error["loc"]
                ),
                "type": error["type"],
                "msg": (
                    "Invalid value"
                    if error["type"] in {"value_error", "assertion_error"}
                    else error["msg"]
                ),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable) -> Response:
        identifier = uuid4()
        reset = request_id.set(identifier)
        try:
            response = await call_next(request)
        finally:
            request_id.reset(reset)
        response.headers["X-Request-ID"] = str(identifier)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if current.session_https_only:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok", "mode": "api"}

    app.include_router(create_api_router(logs, alert_states))
    app.include_router(
        create_backend_router(
            logs,
            current,
            load_correlation_config(current.correlation_rules_path),
            load_topology(current.topology_config_path),
        )
    )
    app.state.settings = current
    app.state.backend = backend
    app.state.accounts = ApiAccounts(backend, current) if backend is not None else None
    app.state.login_throttle = LoginThrottle()
    return app


app = create_app()
