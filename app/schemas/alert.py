"""Alert Schema v1, shared by ingestion, storage, dashboard and notifications."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictInt,
    StrictStr,
    ValidationInfo,
    field_validator,
    model_validator,
)

DEFAULT_RAW_LOG_MAX_LENGTH = 4096


class AlertSource(StrEnum):
    """Supported alert producers."""

    MOCK = "mock"
    WAZUH = "wazuh"


class DeviceType(StrEnum):
    """Normalized device categories."""

    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    OTHER = "other"


class Severity(StrEnum):
    """Normalized alert severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Analyst lifecycle state for an alert."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    MUTED = "muted"


class SchemaModel(BaseModel):
    """Strict base settings shared by Alert Schema v1 models."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


class Device(SchemaModel):
    """Network asset that emitted the event."""

    name: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    type: DeviceType
    vendor: Annotated[StrictStr, Field(max_length=255)] | None = None
    ip: IPvAnyAddress | None = None


class Rule(SchemaModel):
    """Detection rule responsible for the alert."""

    id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    description: Annotated[StrictStr, Field(min_length=1, max_length=1000)]
    level: Annotated[StrictInt, Field(ge=0)]
    groups: list[Annotated[StrictStr, Field(min_length=1, max_length=255)]] = Field(
        default_factory=list
    )
    catalog_id: Annotated[StrictStr, Field(min_length=1, max_length=255)] | None = None


Port = Annotated[StrictInt, Field(ge=1, le=65535)]
VlanId = Annotated[StrictInt, Field(ge=1, le=4094)]


class Network(SchemaModel):
    """Optional network attributes parsed from the source event."""

    src_ip: IPvAnyAddress | None = None
    src_port: Port | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: Port | None = None
    protocol: Annotated[StrictStr, Field(min_length=1, max_length=32)] | None = None
    interface: Annotated[StrictStr, Field(min_length=1, max_length=255)] | None = None
    vlan: VlanId | None = None


class MitreTechnique(SchemaModel):
    """MITRE ATT&CK technique associated with the detection."""

    id: Annotated[StrictStr, Field(min_length=1, max_length=32)]
    name: Annotated[StrictStr, Field(min_length=1, max_length=255)]
    tactic: Annotated[StrictStr, Field(min_length=1, max_length=255)]


def _parse_datetime(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError("timestamp must be a valid ISO 8601 datetime") from error


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


def _digest(*parts: str) -> str:
    identity = "\x1f".join(parts)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


class Alert(SchemaModel):
    """Canonical and fully validated Alert Schema v1 model."""

    schema_version: Literal["1.0"] = "1.0"
    alert_id: StrictStr = ""
    timestamp: datetime
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: AlertSource
    device: Device
    severity: Severity
    rule: Rule
    network: Network = Field(default_factory=Network)
    user: Annotated[StrictStr, Field(min_length=1, max_length=255)] | None = None
    mitre: list[MitreTechnique] = Field(default_factory=list)
    event_count: Annotated[StrictInt, Field(ge=1)] = 1
    status: AlertStatus = AlertStatus.NEW
    acknowledged_by: Annotated[StrictStr, Field(min_length=1, max_length=255)] | None = None
    acknowledged_at: datetime | None = None
    tags: list[Annotated[StrictStr, Field(min_length=1, max_length=255)]] = Field(
        default_factory=list
    )
    raw_log: StrictStr
    dedup_key: StrictStr = ""

    @model_validator(mode="before")
    @classmethod
    def migrate_flat_v0_input(cls, value: Any) -> Any:
        """Accept the former flat constructor while always producing Schema v1."""
        if not isinstance(value, dict) or "device" in value or "rule" in value:
            return value
        if "device_name" not in value and "rule_id" not in value:
            return value
        legacy = dict(value)
        mitre = []
        if legacy.get("mitre_id"):
            mitre = [
                {
                    "id": legacy.get("mitre_id"),
                    "name": legacy.get("mitre_name") or "Unknown",
                    "tactic": legacy.get("mitre_tactic") or "Unknown",
                }
            ]
        acknowledged = bool(legacy.get("acknowledged", False))
        converted: dict[str, Any] = {
            "schema_version": legacy.get("schema_version", "1.0"),
            "alert_id": legacy.get("id", legacy.get("alert_id", "")),
            "timestamp": legacy.get("timestamp"),
            "received_at": legacy.get("received_at", datetime.now(UTC)),
            "source": legacy.get("source", "mock"),
            "device": {
                "name": legacy.get("device_name", "unknown-device"),
                "type": legacy.get("device_type", "other"),
                "vendor": legacy.get("device_vendor"),
                "ip": legacy.get("device_ip"),
            },
            "severity": legacy.get("severity"),
            "rule": {
                "id": legacy.get("rule_id", "unknown"),
                "description": legacy.get("rule_description", "Unclassified event"),
                "level": legacy.get("wazuh_level", 0),
                "groups": legacy.get("groups", []),
                "catalog_id": legacy.get("use_case_id"),
            },
            "network": {
                "src_ip": legacy.get("source_ip"),
                "src_port": legacy.get("src_port"),
                "dst_ip": legacy.get("dest_ip"),
                "dst_port": legacy.get("dst_port"),
                "protocol": legacy.get("protocol"),
                "interface": legacy.get("interface"),
                "vlan": legacy.get("vlan"),
            },
            "user": legacy.get("user"),
            "mitre": mitre,
            "event_count": legacy.get("count", legacy.get("event_count", 1)),
            "status": legacy.get(
                "status", "acknowledged" if acknowledged else "new"
            ),
            "acknowledged_by": legacy.get("acknowledged_by"),
            "acknowledged_at": legacy.get("acknowledged_at"),
            "tags": legacy.get("tags", []),
            "raw_log": legacy.get("raw_log", ""),
            "dedup_key": legacy.get("dedup_key", ""),
        }
        recognized = {
            "acknowledged",
            "acknowledged_at",
            "acknowledged_by",
            "alert_id",
            "count",
            "dedup_key",
            "dest_ip",
            "device_ip",
            "device_name",
            "device_type",
            "device_vendor",
            "dst_port",
            "event_count",
            "groups",
            "id",
            "interface",
            "mitre_id",
            "mitre_name",
            "mitre_tactic",
            "protocol",
            "raw_log",
            "received_at",
            "recommended_response",
            "rule_description",
            "rule_id",
            "schema_version",
            "severity",
            "source",
            "source_ip",
            "src_port",
            "status",
            "tags",
            "timestamp",
            "use_case_id",
            "user",
            "vlan",
            "wazuh_level",
        }
        converted.update({key: item for key, item in legacy.items() if key not in recognized})
        return converted

    @field_validator("timestamp", "received_at", "acknowledged_at", mode="before")
    @classmethod
    def parse_datetime(cls, value: Any) -> Any:
        """Accept ISO 8601 at the boundary while retaining strict field types."""
        if value is None:
            return None
        return _parse_datetime(value)

    @field_validator("timestamp", "received_at", "acknowledged_at")
    @classmethod
    def normalize_datetime(cls, value: datetime | None) -> datetime | None:
        """Reject naive datetimes and normalize every accepted time to UTC."""
        return _utc(value) if value is not None else None

    @field_validator("raw_log")
    @classmethod
    def truncate_raw_log(cls, value: str, info: ValidationInfo) -> str:
        """Bound hostile raw input using a caller-configurable validation context."""
        context = info.context or {}
        raw_limit = context.get("raw_log_max_length", DEFAULT_RAW_LOG_MAX_LENGTH)
        if isinstance(raw_limit, bool) or not isinstance(raw_limit, int) or raw_limit < 1:
            raise ValueError("raw_log_max_length must be a positive integer")
        return value[:raw_limit]

    @model_validator(mode="after")
    def derive_identifiers(self) -> Alert:
        """Derive stable identifiers from normalized canonical values."""
        timestamp_bucket = self.timestamp.replace(microsecond=0).isoformat()
        source_ip = str(self.network.src_ip or "")
        alert_id = _digest(
            self.source.value,
            self.rule.id,
            self.device.name,
            source_ip,
            timestamp_bucket,
        )
        dedup_key = _digest(self.rule.id, self.device.name, source_ip)
        object.__setattr__(self, "alert_id", alert_id)
        object.__setattr__(self, "dedup_key", dedup_key)
        return self

    @property
    def id(self) -> str:
        """Compatibility alias for the previous flat model."""
        return self.alert_id

    @property
    def device_name(self) -> str:
        return self.device.name

    @property
    def device_type(self) -> str:
        return self.device.type.value

    @property
    def source_ip(self) -> str | None:
        return str(self.network.src_ip) if self.network.src_ip else None

    @property
    def dest_ip(self) -> str | None:
        return str(self.network.dst_ip) if self.network.dst_ip else None

    @property
    def rule_id(self) -> str:
        return self.rule.id

    @property
    def rule_description(self) -> str:
        return self.rule.description

    @property
    def use_case_id(self) -> str | None:
        return self.rule.catalog_id

    @property
    def mitre_id(self) -> str | None:
        return self.mitre[0].id if self.mitre else None

    @property
    def mitre_name(self) -> str | None:
        return self.mitre[0].name if self.mitre else None
