"""Revocable API sessions backed by PostgreSQL and the existing PBKDF2 verifier."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Lock
from time import monotonic
from typing import Annotated

import psycopg
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings
from app.schemas.backend import (
    Login,
    Principal,
    Role,
    SessionResponse,
    UserCreate,
    UserRecord,
    UserUpdate,
)
from app.storage.backend import DuplicateResource, PostgresBackendStorage, audit
from app.storage.base import StorageError
from app.web.auth import PBKDF2_ITERATIONS, hash_password, require_api_csrf, verify_password

DUMMY_HASH = (
    f"pbkdf2_sha256${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
bearer = HTTPBearer(auto_error=False)


def unauthenticated() -> HTTPException:
    return HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})


def _digest(token: str, *, cookie: bool = False) -> str:
    value = f"cookie:{token}" if cookie else token
    return hashlib.sha256(value.encode()).hexdigest()


class LoginThrottle:
    """Bound costly verification across both login forms in the dashboard process."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._attempts: deque[tuple[float, str]] = deque()

    def allow(self, client: str) -> bool:
        now = monotonic()
        with self._lock:
            while self._attempts and self._attempts[0][0] <= now - 60:
                self._attempts.popleft()
            if len(self._attempts) >= 120 or sum(ip == client for _, ip in self._attempts) >= 10:
                return False
            self._attempts.append((now, client))
            return True


class ApiAccounts:
    def __init__(self, storage: PostgresBackendStorage, settings: Settings) -> None:
        self.storage = storage
        self.settings = settings
        self.bootstrap_version = hmac.new(
            settings.session_secret.encode(), settings.admin_password_hash.encode(), "sha256"
        ).hexdigest()

    def login(self, credentials: Login, *, cookie: bool = False) -> SessionResponse | None:
        configured_admin = credentials.username == self.settings.admin_username
        account = None
        with self.storage._connect() as connection:
            if not configured_admin and not cookie and "\x00" not in credentials.username:
                account = connection.execute(
                    "SELECT * FROM api_users WHERE username = %s FOR SHARE", (credentials.username,)
                ).fetchone()
            encoded = (
                self.settings.admin_password_hash
                if configured_admin
                else (account["password_hash"] if account is not None else "")
            )
            valid = verify_password(credentials.password, encoded or DUMMY_HASH)
            if not (encoded and valid and (configured_admin or (account and account["enabled"]))):
                audit(
                    connection,
                    "auth.login",
                    "session",
                    None,
                    credentials.username if account is not None or configured_admin else None,
                    outcome="failure",
                )
                return None
            role = Role(account["role"]) if account is not None else Role.ADMIN
            token = secrets.token_urlsafe(32)
            lifetime = 8 * 60 * 60 if cookie else self.settings.api_session_seconds
            expires = datetime.now(UTC) + timedelta(seconds=lifetime)
            connection.execute("DELETE FROM api_sessions WHERE expires_at <= now()")
            # The configured bootstrap account lives outside api_users.
            connection.execute(
                "INSERT INTO api_sessions (token_hash, username, bootstrap_version, expires_at) "
                "VALUES (%s, %s, %s, %s)",
                (
                    _digest(token, cookie=cookie),
                    credentials.username,
                    self.bootstrap_version if configured_admin else None,
                    expires,
                ),
            )
            audit(connection, "auth.login", "session", None, credentials.username)
        return SessionResponse(
            access_token=token,
            expires_at=expires,
            user=Principal(username=credentials.username, role=role),
        )

    def authenticate(self, token: str, *, cookie: bool = False) -> Principal | None:
        if len(token) != 43 or not token.isascii():
            return None
        with self.storage._connect() as connection:
            row = connection.execute(
                """
                SELECT session.username, session.bootstrap_version, account.role, account.enabled
                FROM api_sessions AS session
                LEFT JOIN api_users AS account USING (username)
                WHERE token_hash = %s AND expires_at > now()
                """,
                (_digest(token, cookie=cookie),),
            ).fetchone()
        if row is None:
            return None
        is_configured = row["username"] == self.settings.admin_username
        version = row["bootstrap_version"]
        if (
            version
            and is_configured
            and self.settings.admin_password_hash
            and hmac.compare_digest(version, self.bootstrap_version)
        ):
            return Principal(username=row["username"], role=Role.ADMIN)
        if not version and not is_configured and row["enabled"]:
            return Principal(username=row["username"], role=row["role"])
        return None

    def logout(self, token: str, actor: str, *, cookie: bool = False) -> None:
        with self.storage._connect() as connection:
            connection.execute(
                "DELETE FROM api_sessions WHERE token_hash = %s", (_digest(token, cookie=cookie),)
            )
            audit(connection, "auth.logout", "session", None, actor)

    def users(self, page: int, size: int) -> list[UserRecord]:
        with self.storage._connect() as connection:
            rows = connection.execute(
                "SELECT username, role, enabled FROM api_users "
                "ORDER BY username LIMIT %s OFFSET %s",
                (size, (page - 1) * size),
            ).fetchall()
        return [UserRecord.model_validate(row) for row in rows]

    def create_user(self, body: UserCreate, actor: str) -> UserRecord:
        if body.username.casefold() == self.settings.admin_username.casefold():
            raise DuplicateResource("User already exists")
        encoded = hash_password(body.password)
        try:
            with self.storage._connect() as connection:
                row = connection.execute(
                    """
                    INSERT INTO api_users (username, password_hash, role) VALUES (%s, %s, %s)
                    RETURNING username, role, enabled
                    """,
                    (body.username, encoded, body.role),
                ).fetchone()
                audit(
                    connection,
                    "user.create",
                    "user",
                    body.username,
                    actor,
                    metadata={"role": body.role},
                )
        except StorageError as exc:
            if isinstance(exc.__cause__, psycopg.errors.UniqueViolation):
                raise DuplicateResource("User already exists") from exc
            raise
        return UserRecord.model_validate(row)

    def update_user(self, username: str, body: UserUpdate, actor: str) -> UserRecord | None:
        encoded = hash_password(body.password) if body.password is not None else None
        with self.storage._connect() as connection:
            prior = connection.execute(
                "SELECT role, enabled FROM api_users WHERE username = %s FOR UPDATE", (username,)
            ).fetchone()
            if prior is None:
                return None
            row = connection.execute(
                """
                UPDATE api_users SET role = COALESCE(%s, role), enabled = COALESCE(%s, enabled),
                    password_hash = COALESCE(%s, password_hash)
                WHERE username = %s
                RETURNING username, role, enabled
                """,
                (body.role, body.enabled, encoded, username),
            ).fetchone()
            permissions_changed = row["role"] != prior["role"] or row["enabled"] != prior["enabled"]
            if permissions_changed or encoded is not None:
                connection.execute("DELETE FROM api_sessions WHERE username = %s", (username,))
            if permissions_changed:
                audit(
                    connection,
                    "user.role",
                    "user",
                    username,
                    actor,
                    metadata={
                        "previous_role": prior["role"],
                        "role": body.role,
                        "enabled": body.enabled,
                    },
                )
            if encoded is not None:
                audit(connection, "user.password", "user", username, actor)
        return UserRecord.model_validate(row)


def _cookie_principal(request: Request) -> Principal | None:
    settings: Settings = request.app.state.settings
    if request.session.get("user") != settings.admin_username:
        return None
    accounts: ApiAccounts | None = request.app.state.accounts
    if accounts is None:
        return Principal(username=settings.admin_username, role=Role.ADMIN)
    token = request.session.get("legacy_session")
    return accounts.authenticate(token, cookie=True) if isinstance(token, str) else None


def require_user(request: Request) -> str:
    if actor := _cookie_principal(request):
        return actor.username
    raise HTTPException(303, "Authentication required", headers={"Location": "/login"})


def logout_cookie(request: Request, actor: str) -> None:
    accounts: ApiAccounts | None = request.app.state.accounts
    if accounts is not None:
        accounts.logout(request.session["legacy_session"], actor, cookie=True)
    request.session.clear()


def principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if "authorization" in request.headers:
        accounts: ApiAccounts | None = request.app.state.accounts
        if credentials and accounts and (actor := accounts.authenticate(credentials.credentials)):
            return actor
        raise unauthenticated()
    if actor := _cookie_principal(request):
        return actor
    if request.app.state.backend is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Session"})
    raise unauthenticated()


def roles(*allowed: Role) -> Callable[..., Principal]:
    def permitted(actor: Annotated[Principal, Depends(principal)]) -> Principal:
        if actor.role not in allowed:
            raise HTTPException(403, "Permission denied")
        return actor

    return permitted


def mutation_csrf(
    request: Request,
    _actor: Annotated[Principal, Depends(principal)],
) -> None:
    if "authorization" not in request.headers:
        require_api_csrf(request)


def consume_login_attempt(request: Request) -> None:
    throttle: LoginThrottle = request.app.state.login_throttle
    if not throttle.allow(request.client.host if request.client else "unknown"):
        raise HTTPException(429, "Too many login attempts", headers={"Retry-After": "60"})
