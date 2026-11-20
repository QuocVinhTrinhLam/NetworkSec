"""Normalize untrusted alert documents into one predictable schema."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, cast

from app.schemas.alert import Alert, AlertSource, Device, MitreTechnique, Network, Rule
from app.services.catalog import RulesCatalog, SeverityMapper

_IP_FIELDS = {
    "source": ("data.srcip", "data.src_ip", "source.ip", "srcip"),
    "dest": ("data.dstip", "data.dst_ip", "destination.ip", "dstip"),
}

_PORT_FIELDS = {
    "source": ("data.srcport", "data.src_port", "source.port", "srcport"),
    "dest": ("data.dstport", "data.dst_port", "destination.port", "dstport"),
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


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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


def infer_vendor(document: dict[str, Any], device_name: str) -> str | None:
    haystack = " ".join(
        (
            device_name,
            str(_nested(document, "decoder.name", "")),
            str(document.get("location", "")),
        )
    ).lower()
    if "pfsense" in haystack:
        return "Netgate/pfSense"
    if "opnsense" in haystack:
        return "OPNsense"
    if re.search(r"mikrotik|routeros|winbox", haystack):
        return "MikroTik"
    if re.search(r"cisco|ios|iol", haystack):
        return "Cisco"
    if re.search(r"openvswitch|ovs", haystack):
        return "Open vSwitch"
    return None


def normalize_alert(
    document: dict[str, Any],
    severity_mapper: SeverityMapper,
    rules_catalog: RulesCatalog,
    external_id: str | None = None,
    *,
    source: AlertSource | str = AlertSource.MOCK,
    raw_log_max_length: int = 4096,
) -> Alert:
    """Convert one source document into an internal Alert.

    Raw fields remain plain data. Templates and Telegram formatters escape them at
    the output boundary because log content can be controlled by an attacker.
    """
    rule_value = document.get("rule")
    rule = cast(dict[str, Any], rule_value) if isinstance(rule_value, dict) else {}
    groups = _as_list(rule.get("groups"))
    rule_id = str(rule.get("id", "unknown"))
    level = _optional_int(rule.get("level")) or 0
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
    mitre_value = rule.get("mitre")
    mitre_data = cast(dict[str, Any], mitre_value) if isinstance(mitre_value, dict) else {}
    mitre_ids = _as_list(mitre_data.get("id"))
    mitre_names = _as_list(mitre_data.get("technique"))
    if catalog_entry:
        techniques = [
            MitreTechnique(id=item.id, name=item.name, tactic=item.tactic)
            for item in catalog_entry.mitre
        ]
    else:
        techniques = [
            MitreTechnique(
                id=technique_id[:32],
                name=(mitre_names[index] if index < len(mitre_names) else "Unknown")[:255],
                tactic="Unknown",
            )
            for index, technique_id in enumerate(mitre_ids)
            if technique_id
        ]
    raw_value = document.get("full_log", document.get("message", document))
    raw_log = raw_value if isinstance(raw_value, str) else json.dumps(raw_value, ensure_ascii=False)

    _ = external_id  # Source IDs are intentionally ignored; Alert derives its stable identity.
    user_value = _first(document, ("data.srcuser", "data.dstuser", "user.name", "data.user"))
    return Alert.model_validate(
        {
            "timestamp": _timestamp(document.get("@timestamp", document.get("timestamp"))),
            "source": source,
            "device": Device(
                name=device_name,
                type=infer_device_type(document, device_name, groups),
                vendor=infer_vendor(document, device_name),
                ip=_first(document, ("agent.ip", "data.device_ip")),
            ),
            "severity": severity,
            "rule": Rule(
                id=rule_id[:128],
                description=str(rule.get("description") or "Unclassified event")[:1000],
                level=level,
                groups=[value[:255] for value in groups if value],
                catalog_id=catalog_entry.id if catalog_entry else None,
            ),
            "network": Network(
                src_ip=_first(document, _IP_FIELDS["source"]),
                src_port=_optional_int(_first(document, _PORT_FIELDS["source"])),
                dst_ip=_first(document, _IP_FIELDS["dest"]),
                dst_port=_optional_int(_first(document, _PORT_FIELDS["dest"])),
                protocol=_first(document, ("data.protocol", "network.transport")),
                interface=_first(
                    document,
                    ("data.interface", "data.ifname", "observer.ingress.interface.name"),
                ),
                vlan=_optional_int(_first(document, ("data.vlan", "network.vlan.id"))),
            ),
            "user": str(user_value)[:255] if user_value not in (None, "") else None,
            "mitre": techniques,
            "tags": [value[:255] for value in groups if value],
            "raw_log": raw_log,
        },
        context={"raw_log_max_length": raw_log_max_length},
    )
