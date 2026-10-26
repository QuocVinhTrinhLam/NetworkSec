"""Alert source adapters and environment-driven selection."""

from app.adapters.base import BaseAdapter
from app.adapters.mock import MockAdapter
from app.adapters.wazuh import WazuhAdapter
from app.config import Settings


def build_adapter(settings: Settings) -> BaseAdapter:
    """Build the configured source without silently falling back to another adapter."""
    if settings.alert_source == "mock":
        return MockAdapter()
    if settings.alert_source == "wazuh":
        return WazuhAdapter()
    raise ValueError("ALERT_SOURCE must be either 'mock' or 'wazuh'")


__all__ = ["BaseAdapter", "MockAdapter", "WazuhAdapter", "build_adapter"]
