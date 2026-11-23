"""Versioned contracts for deterministic event correlation."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from app.schemas.event import BoundedName, EventSeverity, EventType, NormalizedEvent

GroupField = Literal["device_name", "interface_name", "event_family", "event_type"]
RequiredField = Literal["device_name", "interface_name"]
RuleId = Annotated[StrictStr, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_-]*$")]


class CorrelationRule(BaseModel):
    """One allowlisted correlation rule loaded from YAML."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: RuleId
    enabled: StrictBool = True
    event_family: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    event_types: Annotated[tuple[EventType, ...], Field(min_length=1)]
    group_by: Annotated[tuple[GroupField, ...], Field(min_length=1)]
    required_fields: tuple[RequiredField, ...] = ()
    window_seconds: Annotated[StrictInt, Field(ge=1, le=86400)]
    notification_cooldown_seconds: Annotated[StrictInt, Field(ge=1, le=604800)]

    @model_validator(mode="after")
    def validate_unique_values(self) -> CorrelationRule:
        if len(set(self.event_types)) != len(self.event_types):
            raise ValueError("event_types must not contain duplicates")
        if len(set(self.group_by)) != len(self.group_by):
            raise ValueError("group_by must not contain duplicates")
        if len(set(self.required_fields)) != len(self.required_fields):
            raise ValueError("required_fields must not contain duplicates")
        return self


class OspfEndpoint(BaseModel):
    """Inventory coordinates of a reporting interface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    router_id: IPv4Address
    device_name: BoundedName
    interface_name: BoundedName


class OspfLink(BaseModel):
    """A configured point-to-point adjacency within the correlation scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: BoundedName
    area: IPv4Address
    endpoints: tuple[OspfEndpoint, OspfEndpoint]

    @model_validator(mode="after")
    def validate_endpoints(self) -> OspfLink:
        first, second = self.endpoints
        if first.router_id == second.router_id or first.device_name == second.device_name:
            raise ValueError("OSPF link endpoints must identify two distinct routers")
        return self


class OspfCorrelationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = True
    scope: BoundedName
    max_clock_skew_seconds: Annotated[StrictInt, Field(ge=0, le=86400)] = 300
    links: tuple[OspfLink, ...] = ()

    @model_validator(mode="after")
    def validate_unique_link_ids(self) -> OspfCorrelationConfig:
        if len({link.id for link in self.links}) != len(self.links):
            raise ValueError("OSPF link IDs must be unique within the scope")
        return self


class CorrelationConfig(BaseModel):
    """Versioned top-level correlation configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    rules: Annotated[tuple[CorrelationRule, ...], Field(min_length=1)]
    ospf: OspfCorrelationConfig | None = None

    @model_validator(mode="after")
    def validate_unique_rule_ids(self) -> CorrelationConfig:
        rule_ids = [rule.id for rule in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("correlation rule IDs must be unique")
        return self


class AggregatedAlert(BaseModel):
    """Persisted alert state derived from one fixed event-time window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    aggregate_id: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    rule_id: RuleId
    event_family: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    group_key: dict[StrictStr, StrictStr]
    device_name: StrictStr | None = None
    interface_name: StrictStr | None = None
    event_types: Annotated[tuple[EventType, ...], Field(min_length=1)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    count: Annotated[StrictInt, Field(ge=1)]
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    severity: EventSeverity
    notification_cooldown_seconds: Annotated[StrictInt, Field(ge=1)]
    last_notification_at: AwareDatetime | None = None
    notification_count: Annotated[StrictInt, Field(ge=0)] = 0


class CorrelatedRawEvent(BaseModel):
    """Trace record linking an immutable raw event to its aggregate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    aggregate_id: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    event_timestamp: AwareDatetime
    received_at: AwareDatetime
    event_type: EventType
    severity: EventSeverity
    raw_message: StrictStr
    event: NormalizedEvent


class OspfAdjacencyKey(BaseModel):
    """Inventory link ID or a reporter-local interface when the peer side is unknown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: BoundedName
    protocol: Literal["ospf"] = "ospf"
    area: IPv4Address
    router_ids: tuple[IPv4Address, IPv4Address]
    link_id: BoundedName | None = None
    local_interface: tuple[BoundedName, BoundedName] | None = None


class OspfReporterState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    router_id: IPv4Address
    last_down_at: AwareDatetime
    uncertain_until: AwareDatetime | None = None
    full_at: AwareDatetime | None = None


class OspfIncidentEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: StrictStr
    timestamp: AwareDatetime
    observed_at: AwareDatetime
    reporter_router_id: IPv4Address
    event_type: EventType


class OspfIncident(BaseModel):
    """A technical outage derived from OSPF observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: StrictStr
    first_down_at: AwareDatetime
    recovered_at: AwareDatetime | None = None
    reporters: tuple[OspfReporterState, ...]
    evidence: tuple[OspfIncidentEvidence, ...]

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(item.event_id for item in self.evidence)


class OspfCorrelationSnapshot(BaseModel):
    """Revisioned projection for reconciling a downstream incident store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adjacency_id: StrictStr
    adjacency: OspfAdjacencyKey
    revision: Annotated[StrictInt, Field(ge=0)]
    incidents: tuple[OspfIncident, ...]
    unreliable_event_ids: tuple[StrictStr, ...] = ()


class CorrelationResult(BaseModel):
    """Outcome returned for every normalized event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matched: StrictBool
    duplicate: StrictBool = False
    reason: StrictStr | None = None
    alert: AggregatedAlert | None = None
    ospf: OspfCorrelationSnapshot | None = None


class NotificationClaim(BaseModel):
    """Atomic cooldown decision for a downstream notification worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: StrictBool
    aggregate_id: StrictStr
    claimed_at: AwareDatetime | None = None
    next_allowed_at: AwareDatetime | None = None
