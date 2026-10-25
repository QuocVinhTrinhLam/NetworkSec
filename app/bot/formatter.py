"""HTML-safe Telegram alert formatting."""

from __future__ import annotations

import html
from typing import Any

EMOJI = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def _safe(value: Any, fallback: str = "-") -> str:
    return html.escape(str(value if value not in (None, "") else fallback), quote=True)


def format_alert(alert: dict[str, Any], count: int = 1) -> str:
    """Escape every field because network logs are attacker-controlled."""
    severity = str(alert.get("severity", "medium")).lower()
    title = _safe(alert.get("rule_description", "Security alert"))
    lines = [
        f"{EMOJI.get(severity, '⚪')} <b>[{severity.upper()}] {title}</b>",
        (
            f"Device: <code>{_safe(alert.get('device_name'))}</code> "
            f"({_safe(alert.get('device_type'))})"
        ),
        (
            f"Source: <code>{_safe(alert.get('source_ip'))}</code> → "
            f"<code>{_safe(alert.get('dest_ip'))}</code>"
        ),
        f"Rule: <code>{_safe(alert.get('rule_id'))}</code> | MITRE: {_safe(alert.get('mitre_id'))}",
        f"Time: {_safe(alert.get('timestamp'))} | Count: <b>{max(1, count)}</b>",
    ]
    if alert.get("recommended_response"):
        lines.append(f"Recommended: {_safe(alert['recommended_response'])}")
    return "\n".join(lines)
