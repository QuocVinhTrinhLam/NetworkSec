from pathlib import Path

import pytest

from app.config import Settings
from app.main import create_app
from app.web.auth import hash_password, verify_password


def test_missing_session_secret_is_rejected(tmp_path: Path) -> None:
    settings = Settings(
        database_path=tmp_path / "missing-secret.db",
        session_secret="",
    )
    with pytest.raises(RuntimeError, match="SESSION_SECRET is required"):
        create_app(settings)


def test_password_hash_round_trip_and_wrong_password() -> None:
    encoded = hash_password("correct horse battery staple", iterations=10_000)
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("correct horse battery staple", "malformed")


def test_public_bind_rejects_placeholder_session_secret(tmp_path: Path) -> None:
    settings = Settings(
        bind_host="0.0.0.0",
        database_path=tmp_path / "monitor.db",
        session_secret="replace-with-at-least-32-random-characters",
    )

    with pytest.raises(RuntimeError, match="public bind"):
        create_app(settings)


def test_local_development_allows_placeholder_session_secret(tmp_path: Path) -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        database_path=tmp_path / "monitor.db",
        session_secret="development-only-change-me",
    )

    app = create_app(settings)

    assert app.state.settings.bind_host == "127.0.0.1"
