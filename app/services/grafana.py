"""Build browser-facing Grafana links from deployment configuration."""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit

from app.config import Settings
from app.services.backend import EventFilters

_VARIABLE = re.compile(r"^[a-zA-Z0-9_-]{1,80}$")
_FILTERS = {"device", "device_id", "severity", "category", "incident"}


def dashboard_link(
    settings: Settings,
    filters: EventFilters,
    incident_id: str | None,
    device_name_fallback: str | None = None,
) -> str | None:
    if not settings.grafana_public_url:
        return None
    url = urlsplit(settings.grafana_public_url)
    if (
        url.scheme not in ("http", "https")
        or not url.hostname
        or url.hostname in {"loki", "grafana", "postgres", "dashboard"}
        or url.username is not None
        or url.query
        or url.fragment
        or not _VARIABLE.fullmatch(settings.grafana_dashboard_uid)
    ):
        raise ValueError("Invalid public Grafana URL or dashboard UID")
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
