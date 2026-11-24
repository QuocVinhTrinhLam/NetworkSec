"""Build browser-facing Grafana links from deployment configuration."""

from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import SplitResult, urlencode, urlsplit

from app.config import Settings
from app.services.backend import EventFilters

_VARIABLE = re.compile(r"^[a-zA-Z0-9_-]{1,80}$")
_FILTERS = {"device", "device_id", "severity", "category", "incident"}
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_INTERNAL_HOSTS = {"api", "dashboard", "grafana", "loki", "postgres"}


def _grafana_url(base: str, *, for_notification: bool = False) -> SplitResult:
    if any(character.isspace() or ord(character) < 32 for character in base):
        raise ValueError("Invalid public Grafana URL")
    url = urlsplit(base)
    host = (url.hostname or "").rstrip(".")
    try:
        address = ip_address(host)
    except ValueError:
        address = None
    if (
        url.scheme not in ("http", "https")
        or not host
        or host in _INTERNAL_HOSTS
        or (address is None and not _HOST.fullmatch(host))
        or url.username is not None
        or url.query
        or url.fragment
        or url.port == 0
        or (
            for_notification
            and (
                host.split(".")[-1] == "localhost"
                or (address is not None and (address.is_loopback or address.is_unspecified))
            )
        )
    ):
        raise ValueError("Invalid public Grafana URL")
    return url


def incident_link(settings: Settings, incident_id: str) -> str | None:
    """Link directly to a PostgreSQL incident from an operational notification."""
    try:
        url = _grafana_url(settings.grafana_public_url, for_notification=True)
    except ValueError:
        return None
    query = urlencode({"var-incident": incident_id})
    return f"{url.geturl().rstrip('/')}/d/network-incident-operations?{query}"


def dashboard_link(
    settings: Settings,
    filters: EventFilters,
    incident_id: str | None,
    device_name_fallback: str | None = None,
) -> str | None:
    if not settings.grafana_public_url:
        return None
    url = _grafana_url(settings.grafana_public_url)
    if not _VARIABLE.fullmatch(settings.grafana_dashboard_uid):
        raise ValueError("Invalid Grafana dashboard UID")
    mapping: dict[str, str] = {}
    for pair in filter(None, settings.grafana_variable_mapping.split(",")):
        key, _, name = pair.strip().partition("=")
        if key not in _FILTERS or not _VARIABLE.fullmatch(name) or key in mapping:
            raise ValueError("Invalid Grafana variable mapping")
        mapping[key] = name
    if len(set(mapping.values())) != len(mapping):
        raise ValueError("Grafana variable names must be unique")
    parameters = {
        "from": str(int(filters.start.timestamp() * 1000)),
        "to": str(int(filters.end.timestamp() * 1000)),
    }
    for key, value in (
        (
            "device",
            filters.device_name or (device_name_fallback if "device_id" not in mapping else None),
        ),
        ("device_id", str(filters.device_id) if filters.device_id else None),
        ("severity", filters.severity),
        ("category", filters.category),
        ("incident", incident_id),
    ):
        if key in mapping and value:
            parameters[f"var-{mapping[key]}"] = value
    return f"{url.geturl().rstrip('/')}/d/{settings.grafana_dashboard_uid}?{urlencode(parameters)}"
