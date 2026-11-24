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

    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "Network Event Management"))
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    app_url: str = field(default_factory=lambda: os.getenv("APP_URL", "http://localhost:8000"))
    bind_host: str = field(default_factory=lambda: os.getenv("BIND_HOST", "127.0.0.1"))
    database_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "monitor.db"))
        )
    )
    postgres_dsn: str = field(default_factory=lambda: os.getenv("POSTGRES_DSN", ""))
    postgres_migrations_path: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "POSTGRES_MIGRATIONS_PATH",
                str(BASE_DIR / "migrations" / "postgresql"),
            )
        )
    )
    postgres_connect_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("POSTGRES_CONNECT_TIMEOUT_SECONDS", "5"))
    )
    loki_url: str = field(default_factory=lambda: os.getenv("LOKI_URL", "http://127.0.0.1:3100"))
    loki_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("LOKI_TIMEOUT_SECONDS", "5"))
    )
    processor_spool_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("PROCESSOR_SPOOL_PATH", str(BASE_DIR / "data" / "processor.jsonl"))
        )
    )
    processor_state_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("PROCESSOR_STATE_PATH", str(BASE_DIR / "data" / "processor-state.db"))
        )
    )
    correlation_database_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("CORRELATION_DATABASE_PATH", str(BASE_DIR / "data" / "correlation.db"))
        )
    )
    correlation_rules_path: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "CORRELATION_RULES_PATH",
                str(BASE_DIR / "config" / "correlation_rules.yaml"),
            )
        )
    )
    processor_source_timezone: str = field(
        default_factory=lambda: os.getenv("PROCESSOR_SOURCE_TIMEZONE", "UTC")
    )
    processor_poll_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("PROCESSOR_POLL_INTERVAL_SECONDS", "0.25"))
    )
    processor_retry_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("PROCESSOR_RETRY_INTERVAL_SECONDS", "2"))
    )
    processor_health_max_age_seconds: int = field(
        default_factory=lambda: int(os.getenv("PROCESSOR_HEALTH_MAX_AGE_SECONDS", "30"))
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
    admin_username: str = field(default_factory=lambda: os.getenv("ADMIN_USERNAME", "admin"))
    admin_password_hash: str = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD_HASH", ""))
    session_secret: str = field(default_factory=lambda: os.getenv("SESSION_SECRET", ""))
    session_https_only: bool = field(default_factory=lambda: _bool("SESSION_HTTPS_ONLY", False))
    frontend_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            origin.strip()
            for origin in os.getenv("FRONTEND_ORIGINS", "").split(",")
            if origin.strip()
        )
    )
    trusted_hosts: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            host.strip()
            for host in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
            if host.strip()
        )
    )
    api_session_seconds: int = field(
        default_factory=lambda: int(os.getenv("API_SESSION_SECONDS", "3600"))
    )
    topology_config_path: Path | None = field(
        default_factory=lambda: (
            Path(value) if (value := os.getenv("TOPOLOGY_CONFIG_PATH")) else None
        )
    )
    grafana_public_url: str = field(default_factory=lambda: os.getenv("GRAFANA_PUBLIC_URL", ""))
    grafana_dashboard_uid: str = field(
        default_factory=lambda: os.getenv("GRAFANA_DASHBOARD_UID", "network-event-kpis")
    )
    grafana_variable_mapping: str = field(
        default_factory=lambda: os.getenv(
            "GRAFANA_VARIABLE_MAPPING",
            "device=device,device_id=device_id,severity=severity,category=category,incident=incident",
        )
    )
    device_silent_minutes: int = field(
        default_factory=lambda: int(os.getenv("DEVICE_SILENT_MINUTES", "15"))
    )


def get_settings() -> Settings:
    """Build settings at call time so tests can safely change the environment."""
    return Settings()
