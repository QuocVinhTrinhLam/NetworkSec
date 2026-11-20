"""Versioned normalized network event contract for parsed Syslog records."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

MAX_RAW_MESSAGE_BYTES = 32 * 1024


class EventVendor(StrEnum):
    """Vendors with a verified parser and fixture."""

    CISCO = "cisco"
    MIKROTIK = "mikrotik"
    PFSENSE = "pfsense"


class EventType(StrEnum):
    """Normalized network operations and security event categories."""

    LINK_UP = "link_up"
    LINK_DOWN = "link_down"
    PORT_FLAP = "port_flap"
    ROUTING_NEIGHBOR_DOWN = "routing_neighbor_down"
    CONFIGURATION_CHANGE = "configuration_change"
    LOGIN_FAILURE = "login_failure"
    ACL_DENY = "acl_deny"
    PORT_SECURITY = "port_security"


class EventSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNKNOWN = "unknown"


class ParseStatus(StrEnum):
    PARSED = "parsed"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"


Port = Annotated[StrictInt, Field(ge=1, le=65535)]
BoundedName = Annotated[StrictStr, Field(min_length=1, max_length=255)]
OptionalBoundedName = Annotated[StrictStr, Field(min_length=1, max_length=255)] | None


class NormalizedEvent(BaseModel):
    """Strict, immutable event produced by a verified vendor parser."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    schema_version: Literal["1.0"] = "1.0"
    event_id: StrictStr = ""
    timestamp: AwareDatetime
    received_at: AwareDatetime
    vendor: EventVendor
    product: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    event_type: EventType
    severity: EventSeverity
    outcome: EventOutcome = EventOutcome.UNKNOWN
    device_name: OptionalBoundedName = None
    message: Annotated[StrictStr, Field(min_length=1, max_length=4096)]
    raw_message: Annotated[StrictStr, Field(min_length=1, max_length=MAX_RAW_MESSAGE_BYTES)]
    rule_id: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None = None
    rule_tracker: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None = None
    interface_name: OptionalBoundedName = None
    interface_state: Literal["up", "down"] | None = None
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: Port | None = None
    destination_port: Port | None = None
    protocol: Annotated[StrictStr, Field(min_length=1, max_length=32)] | None = None
    direction: Literal["in", "out"] | None = None
    action: Annotated[StrictStr, Field(min_length=1, max_length=32)] | None = None
    username: OptionalBoundedName = None
    auth_method: Annotated[StrictStr, Field(min_length=1, max_length=64)] | None = None
    session: Annotated[StrictStr, Field(min_length=1, max_length=64)] | None = None
    mac_address: Annotated[StrictStr, Field(min_length=11, max_length=32)] | None = None
    vendor_severity: Annotated[StrictStr, Field(min_length=1, max_length=32)] | None = None
    parser_name: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    parser_version: Literal["1.0"] = "1.0"

    @field_validator("timestamp", "received_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Store every accepted timestamp in UTC."""
        return value.astimezone(UTC)

    @field_validator("raw_message")
    @classmethod
    def bound_raw_message_bytes(cls, value: str) -> str:
        """Bound UTF-8 bytes as well as code points."""
        if len(value.encode("utf-8")) > MAX_RAW_MESSAGE_BYTES:
            raise ValueError(f"raw_message exceeds {MAX_RAW_MESSAGE_BYTES} UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def derive_event_id(self) -> NormalizedEvent:
        """Derive a replay-stable identity without trusting a caller-supplied ID."""
        identity = "\x1f".join(
            (
                self.schema_version,
                self.vendor.value,
                self.parser_name,
                self.device_name or "",
                self.timestamp.isoformat(),
                self.raw_message,
            )
        )
        object.__setattr__(self, "event_id", hashlib.sha256(identity.encode("utf-8")).hexdigest())
        return self
