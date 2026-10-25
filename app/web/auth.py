"""Password hashing, sessions and CSRF helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from fastapi import HTTPException, Request, status

PBKDF2_ITERATIONS = 390_000


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(digest).decode().rstrip("="),
    )


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), _decode(salt), int(rounds))
        return hmac.compare_digest(digest, _decode(expected))
    except (ValueError, TypeError):
        return False


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return str(token)


def validate_csrf(request: Request, supplied: str) -> None:
    expected = request.session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(str(expected), supplied):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


def require_user(request: Request) -> str:
    user: Any = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
            detail="Authentication required",
        )
    return str(user)
