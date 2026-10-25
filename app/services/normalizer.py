"""Normalize untrusted Wazuh documents into one predictable schema."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from app.models import Alert
from app.services.catalog import RulesCatalog, SeverityMapper

_IP_FIELDS = {
    "source": ("data.srcip", "data.src_ip", "source.ip", "srcip"),
    "dest": ("data.dstip", "data.dst_ip", "destination.ip", "dstip"),
}


def _nested(document: dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    current: Any = document
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return default
        current = current[segment]
    return current


def _first(document: dict[str, Any], paths: tuple[str, ...], default: Any = None) -> Any:
    for path in paths:
        value = _nested(document, path)
        if value not in (None, ""):
            return value
    return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _timestamp(value: Any) -> str:
    if not value:
        return datetime.now(UTC).isoformat(timespec="milliseconds")
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat(timespec="milliseconds")
    except ValueError:
        return datetime.now(UTC).isoformat(timespec="milliseconds")


def infer_device_type(document: dict[str, Any], device_name: str, groups: list[str]) -> str:
    """Infer a broad device type without trusting raw HTML or markup."""
    haystack = " ".join(
        [device_name, str(_nested(document, "decoder.name", "")), *_as_list(groups)]
    ).lower()
    if re.search(r"pfsense|opnsense|firewall|suricata", haystack):
        return "firewall"
    if re.search(r"switch|cisco|openvswitch|port.security|mac.flood", haystack):
        return "switch"
    if re.search(r"router|mikrotik|vyos|winbox", haystack):
        return "router"
    return "other"


def normalize_alert(
    document: dict[str, Any],
    severity_mapper: SeverityMapper,
    rules_catalog: RulesCatalog,
    external_id: str | None = None,
) -> Alert:
    """Convert one Wazuh/OpenSearch document into an internal Alert.

    Raw fields remain plain data. Templates and Telegram formatters escape them at
    the output boundary because log content can be controlled by an attacker.
    """
    rule = document.get("rule") if isinstance(document.get("rule"), dict) else {}
    groups = _as_list(rule.get("groups"))
    rule_id = str(rule.get("id", "unknown"))
    level = int(rule.get("level", 0) or 0)
    catalog_entry = rules_catalog.match(rule_id, groups)
    severity = severity_mapper.map(level)
    if catalog_entry and catalog_entry.severity in {"low", "medium", "high", "critical"}:
        severity = catalog_entry.severity

    device_name = str(
        _first(
            document,
            ("agent.name", "predecoder.hostname", "data.hostname", "location"),
            "unknown-device",
        )
    )[:255]
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    mitre_ids = _as_list(mitre.get("id"))
    mitre_names = _as_list(mitre.get("technique"))
    raw_value = document.get("full_log", document.get("message", document))
    raw_log = raw_value if isinstance(raw_value, str) else json.dumps(raw_value, ensure_ascii=False)

    return Alert(
        id=str(external_id or document.get("_id") or uuid.uuid4()),
        timestamp=_timestamp(document.get("@timestamp", document.get("timestamp"))),
        device_name=device_name,
        device_type=infer_device_type(document, device_name, groups),
        source_ip=_first(document, _IP_FIELDS["source"]),
        dest_ip=_first(document, _IP_FIELDS["dest"]),
        user=_first(document, ("data.srcuser", "data.dstuser", "user.name", "data.user")),
        rule_id=rule_id[:64],
        rule_description=str(rule.get("description", "Unclassified event"))[:500],
        severity=severity,
        mitre_id=mitre_ids[0] if mitre_ids else None,
        mitre_name=mitre_names[0] if mitre_names else None,
        raw_log=raw_log[:65535],
        use_case_id=catalog_entry.id if catalog_entry else None,
        recommended_response=catalog_entry.recommended_response if catalog_entry else None,
        wazuh_level=level,
        groups=groups,
    )
