"""Environment-driven application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_set(value: str) -> set[int]:
    return {int(item.strip()) for item in value.split(",") if item.strip()}


@dataclass(slots=True)
class Settings:
    """Settings loaded from environment variables only."""

    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "Network Security Monitor"))
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    app_url: str = field(default_factory=lambda: os.getenv("APP_URL", "http://localhost:8000"))
    bind_host: str = field(default_factory=lambda: os.getenv("BIND_HOST", "127.0.0.1"))
    database_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "monitor.db"))
        )
    )
    severity_config: Path = field(
        default_factory=lambda: Path(
            os.getenv("SEVERITY_CONFIG", str(BASE_DIR / "config" / "severity_map.yaml"))
        )
    )
    rules_catalog: Path = field(
        default_factory=lambda: Path(
            os.getenv("RULES_CATALOG", str(BASE_DIR / "config" / "rules_catalog.yaml"))
        )
    )
    mock_mode: bool = field(default_factory=lambda: _bool("MOCK_MODE", True))
    alert_source: str = field(default_factory=lambda: os.getenv("ALERT_SOURCE", "mock").lower())
    mock_fixture_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("MOCK_FIXTURE_PATH", str(BASE_DIR / "fixtures" / "alerts.json"))
        )
    )
    raw_log_max_length: int = field(
        default_factory=lambda: int(os.getenv("RAW_LOG_MAX_LENGTH", "4096"))
    )
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    json_logs: bool = field(default_factory=lambda: _bool("JSON_LOGS", False))
    minimum_severity: str = field(
        default_factory=lambda: os.getenv(
            "TELEGRAM_MIN_SEVERITY", os.getenv("MINIMUM_SEVERITY", "medium")
        )
    )
    poll_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("POLL_INTERVAL_SECONDS", "10"))
    )
    notification_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("NOTIFICATION_INTERVAL_SECONDS", "2"))
    )
    dedup_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("DEDUP_WINDOW_SECONDS", "60"))
    )
    telegram_rate_limit: int = field(
        default_factory=lambda: int(
            os.getenv("MAX_MESSAGES_PER_MINUTE", os.getenv("TELEGRAM_RATE_LIMIT", "20"))
        )
    )
    telegram_rate_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("TELEGRAM_RATE_WINDOW_SECONDS", "60"))
    )
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_timezone: str = field(
        default_factory=lambda: os.getenv("TELEGRAM_TIMEZONE", "Asia/Ho_Chi_Minh")
    )
    allowed_chat_ids: set[int] = field(
        default_factory=lambda: _int_set(os.getenv("ALLOWED_CHAT_IDS", ""))
    )
    wazuh_indexer_url: str = field(
        default_factory=lambda: os.getenv("WAZUH_INDEXER_URL", "https://wazuh-indexer:9200")
    )
    wazuh_index_pattern: str = field(
        default_factory=lambda: os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
    )
    wazuh_username: str = field(default_factory=lambda: os.getenv("WAZUH_USERNAME", ""))
    wazuh_password: str = field(default_factory=lambda: os.getenv("WAZUH_PASSWORD", ""))
    wazuh_verify_tls: bool = field(default_factory=lambda: _bool("WAZUH_VERIFY_TLS", True))
    wazuh_ca_file: str = field(default_factory=lambda: os.getenv("WAZUH_CA_FILE", ""))
    wazuh_initial_lookback_minutes: int = field(
        default_factory=lambda: int(os.getenv("WAZUH_INITIAL_LOOKBACK_MINUTES", "5"))
    )
    admin_username: str = field(default_factory=lambda: os.getenv("ADMIN_USERNAME", "admin"))
    admin_password_hash: str = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD_HASH", ""))
    session_secret: str = field(
        default_factory=lambda: os.getenv("SESSION_SECRET", "development-only-change-me")
    )
    session_https_only: bool = field(default_factory=lambda: _bool("SESSION_HTTPS_ONLY", False))
    device_silent_minutes: int = field(
        default_factory=lambda: int(os.getenv("DEVICE_SILENT_MINUTES", "15"))
    )


def get_settings() -> Settings:
    """Build settings at call time so tests can safely change the environment."""
    return Settings()
