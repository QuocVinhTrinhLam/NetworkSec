"""Bounded, HTML-safe Telegram message formatting."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.bot.notification_models import OspfNotification, OspfNotificationKind

EMOJI = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}
TELEGRAM_TEXT_LIMIT = 4096
OSPF_TITLE = {
    OspfNotificationKind.DOWN: "OSPF Neighbor Down",
    OspfNotificationKind.RECOVERED: "OSPF Neighbor Recovered",
    OspfNotificationKind.RECOVERY_RETRACTED: "OSPF recovery no longer confirmed",
    OspfNotificationKind.ACKNOWLEDGED: "OSPF incident acknowledged",
    OspfNotificationKind.OPERATOR_RESOLVED: "OSPF incident resolved by operator",
    OspfNotificationKind.OPERATOR_REOPENED: "OSPF incident reopened by operator",
    OspfNotificationKind.SUPERSEDED: "OSPF incident superseded",
}


def _nested(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _pick(alert: dict[str, Any], *paths: str, fallback: Any = None) -> Any:
    for path in paths:
        value = _nested(alert, path)
        if value not in (None, ""):
            return value
    return fallback


def _safe(value: Any, fallback: str = "-", limit: int = 200) -> str:
    """Escape hostile values and cap their rendered contribution."""
    raw = str(value if value not in (None, "") else fallback)
    chunks: list[str] = []
    rendered_length = 0
    for character in raw:
        escaped_character = html.escape(character, quote=True)
        if rendered_length + len(escaped_character) > max(1, limit):
            break
        chunks.append(escaped_character)
        rendered_length += len(escaped_character)
    return "".join(chunks)


def _local_time(value: Any, timezone_name: str) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        local = parsed.astimezone(ZoneInfo(timezone_name))
        offset = local.strftime("%z")
        offset_label = f"UTC{offset[:3]}:{offset[3:]}" if offset else "UTC"
        return f"{local.strftime('%Y-%m-%d %H:%M:%S')} {offset_label}"
    except (ValueError, KeyError):
        return text[:100] or "-"


def _mitre_text(alert: dict[str, Any]) -> str:
    techniques = alert.get("mitre")
    if isinstance(techniques, list):
        values = [
            str(item.get("id")) for item in techniques if isinstance(item, dict) and item.get("id")
        ]
        if values:
            return ", ".join(values)
    return str(_pick(alert, "mitre_id", fallback="-"))


def format_ospf_notification(claim: OspfNotification, timezone_name: str) -> str:
    adjacency = claim.adjacency
    first, second = adjacency.router_ids
    link = adjacency.link_id or " / ".join(adjacency.local_interface or ())
    severity = claim.severity.value
    lines = [
        f"{EMOJI[severity]} <b>[{severity.upper()}] {OSPF_TITLE[claim.kind]}</b>",
        f"Router IDs <code>{first}</code> ↔ <code>{second}</code> "
        f"· Area <code>{adjacency.area}</code>",
        f"Scope {_safe(adjacency.scope)} · Link {_safe(link)}",
        f"First Down {_local_time(claim.first_seen.isoformat(), timezone_name)}",
        f"Transition {_local_time(claim.occurred_at.isoformat(), timezone_name)}",
        f"Incident <code>{_safe(claim.aggregate_id[:12])}</code>",
    ]
    if claim.actor:
        lines.append(f"Operator {_safe(claim.actor, limit=160)}")
    return "\n".join(lines)


def format_alert(
    alert: dict[str, Any],
    count: int = 1,
    *,
    window_seconds: int = 60,
    timezone_name: str = "Asia/Ho_Chi_Minh",
) -> str:
    """Render one alert without allowing attacker-controlled Telegram markup."""
    severity = str(_pick(alert, "severity", fallback="medium")).lower()
    title = _safe(
        _pick(alert, "rule.description", "rule_description", fallback="Security alert"),
        limit=400,
    )
    device = _safe(_pick(alert, "device.name", "device_name"), limit=180)
    source = _safe(_pick(alert, "network.src_ip", "source_ip"), limit=128)
    destination = _safe(_pick(alert, "network.dst_ip", "dest_ip"), limit=128)
    destination_port = _pick(alert, "network.dst_port", "dst_port")
    destination_text = destination
    if destination_port not in (None, ""):
        destination_text += f":{_safe(destination_port, limit=10)}"
    rule_id = _safe(_pick(alert, "rule.id", "rule_id"), limit=100)
    timestamp = _safe(_local_time(_pick(alert, "timestamp"), timezone_name), limit=120)
    mitre = _safe(_mitre_text(alert), limit=300)
    event_count = max(1, int(_pick(alert, "event_count", "count", fallback=count) or count))
    event_count = max(event_count, count)

    lines = [
        f"{EMOJI.get(severity, '⚪')} <b>[{_safe(severity.upper(), limit=12)}] "
        f"{title} on {device}</b>",
        f"Source: <code>{source}</code> → <code>{destination_text}</code> | "
        f"Rule: <code>{rule_id}</code> | MITRE: {_safe(mitre, limit=300)}",
        f"Time: {timestamp} | Count: <b>{event_count}</b> in {max(1, window_seconds)}s",
    ]

    recommendation = _pick(alert, "recommended_response")
    if isinstance(recommendation, dict):
        recommendation = recommendation.get("vi") or recommendation.get("en")
    if recommendation:
        lines.append(f"Recommended: {_safe(recommendation, limit=800)}")

    status = str(_pick(alert, "status", fallback="new"))
    if status == "acknowledged" or bool(alert.get("acknowledged")):
        actor = _safe(_pick(alert, "acknowledged_by", fallback="analyst"), limit=160)
        lines.append(f"✅ Acknowledged by {actor}")

    message = "\n".join(lines)
    if len(message) > TELEGRAM_TEXT_LIMIT:  # Defensive assertion for future field changes.
        raise ValueError("Telegram message field budgets exceed the platform limit")
    return message
