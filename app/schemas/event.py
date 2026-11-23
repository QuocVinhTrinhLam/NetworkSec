"""Versioned normalized network event contract for parsed Syslog records."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address
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
    ROUTING_NEIGHBOR_UP = "routing_neighbor_up"
    ROUTING_NEIGHBOR_STATE_CHANGE = "routing_neighbor_state_change"
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


class OspfNeighborState(StrEnum):
    DOWN = "DOWN"
    ATTEMPT = "ATTEMPT"
    INIT = "INIT"
    TWO_WAY = "2-WAY"
    EXSTART = "EXSTART"
    EXCHANGE = "EXCHANGE"
    LOADING = "LOADING"
    FULL = "FULL"

    @property
    def classification(self) -> tuple[EventType, EventOutcome]:
        if self is OspfNeighborState.DOWN:
            return EventType.ROUTING_NEIGHBOR_DOWN, EventOutcome.FAILURE
        if self is OspfNeighborState.FULL:
            return EventType.ROUTING_NEIGHBOR_UP, EventOutcome.SUCCESS
        return EventType.ROUTING_NEIGHBOR_STATE_CHANGE, EventOutcome.UNKNOWN


class ParseStatus(StrEnum):
    PARSED = "parsed"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"


Port = Annotated[StrictInt, Field(ge=1, le=65535)]
BoundedName = Annotated[StrictStr, Field(min_length=1, max_length=255)]
OptionalBoundedName = Annotated[StrictStr, Field(min_length=1, max_length=255)] | None
EventSchemaVersion = Literal["1.0", "1.1"]
OSPF_FIELDS = {
    "routing_protocol",
    "ospf_area",
    "local_router_id",
    "neighbor_router_id",
    "neighbor_ip",
    "previous_state",
    "current_state",
}


def _is_none(value: object) -> bool:
    return value is None


class NormalizedEvent(BaseModel):
    """Strict, immutable event produced by a verified vendor parser."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    schema_version: EventSchemaVersion = "1.0"
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
    routing_protocol: Literal["ospf"] | None = Field(default=None, exclude_if=_is_none)
    ospf_area: IPv4Address | None = Field(default=None, exclude_if=_is_none)
    local_router_id: IPv4Address | None = Field(default=None, exclude_if=_is_none)
    neighbor_router_id: IPv4Address | None = Field(default=None, exclude_if=_is_none)
    neighbor_ip: IPv4Address | None = Field(default=None, exclude_if=_is_none)
    previous_state: OspfNeighborState | None = Field(default=None, exclude_if=_is_none)
    current_state: OspfNeighborState | None = Field(default=None, exclude_if=_is_none)

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

    @field_validator(
        "ospf_area", "local_router_id", "neighbor_router_id", "neighbor_ip", mode="before"
    )
    @classmethod
    def require_ipv4_text(cls, value: object) -> object:
        if value is not None and not isinstance(value, (str, IPv4Address)):
            raise ValueError("OSPF addresses and IDs must use dotted IPv4 notation")
        return value

    @model_validator(mode="after")
    def validate_schema_version(self) -> NormalizedEvent:
        if self.schema_version == "1.0":
            if self.model_fields_set & OSPF_FIELDS or self.event_type in {
                EventType.ROUTING_NEIGHBOR_UP,
                EventType.ROUTING_NEIGHBOR_STATE_CHANGE,
            }:
                raise ValueError("OSPF metadata and new event types require schema 1.1")
            return self

        if (
            self.routing_protocol != "ospf"
            or self.neighbor_router_id is None
            or self.previous_state is None
            or self.current_state is None
        ):
            raise ValueError("schema 1.1 requires an OSPF neighbor transition")
        if self.previous_state is self.current_state:
            raise ValueError("OSPF transitions must change state")
        if (self.event_type, self.outcome) != self.current_state.classification:
            raise ValueError("OSPF event type and outcome must match current_state")
        return self

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
