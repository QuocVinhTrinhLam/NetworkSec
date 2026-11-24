"""Contracts for the operational JSON API."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.schemas.event import EventSeverity, EventType, EventVendor, OspfNeighborState

Name = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=255, pattern=r"^[^\x00-\x1f\x7f]+$"
    ),
]
Username = Annotated[
    str, StringConstraints(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$")
]
EventId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
DeviceType = Literal["router", "switch", "firewall", "server", "segment", "other"]
DeviceStatus = Literal["active", "stale", "unknown", "disabled"]


class Category(StrEnum):
    INTERFACE = "interface"
    ROUTING = "routing"
    AUTHENTICATION = "authentication"
    FIREWALL = "firewall"
    CONFIGURATION = "configuration"
    SECURITY = "security"


CATEGORIES = {
    EventType.LINK_UP: Category.INTERFACE,
    EventType.LINK_DOWN: Category.INTERFACE,
    EventType.PORT_FLAP: Category.INTERFACE,
    EventType.ROUTING_NEIGHBOR_DOWN: Category.ROUTING,
    EventType.ROUTING_NEIGHBOR_UP: Category.ROUTING,
    EventType.ROUTING_NEIGHBOR_STATE_CHANGE: Category.ROUTING,
    EventType.LOGIN_FAILURE: Category.AUTHENTICATION,
    EventType.ACL_DENY: Category.FIREWALL,
    EventType.CONFIGURATION_CHANGE: Category.CONFIGURATION,
    EventType.PORT_SECURITY: Category.SECURITY,
}


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Principal(BaseModel):
    username: str
    role: Role


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Login(InputModel):
    username: Annotated[str, Field(min_length=1, max_length=100)]
    password: Annotated[str, Field(min_length=1, max_length=1024, repr=False)]


class SessionResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: AwareDatetime
    user: Principal


class UserCreate(InputModel):
    username: Username
    role: Role
    password: Annotated[str, Field(min_length=12, max_length=1024, repr=False)]


class UserUpdate(InputModel):
    role: Role | None = None
    enabled: bool | None = None
    password: Annotated[str, Field(min_length=12, max_length=1024)] | None = Field(
        default=None, repr=False
    )

    @model_validator(mode="after")
    def validate_update(self) -> UserUpdate:
        if self.role is None and self.enabled is None and self.password is None:
            raise ValueError("Provide a role, enabled state or new password")
        return self


class UserRecord(Principal):
    enabled: bool


class DeviceCreate(InputModel):
    name: Name
    hostname: (
        Annotated[str, Field(max_length=253, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.-]*$")] | None
    ) = None
    management_ip: IPvAnyAddress | None = None
    source_addresses: tuple[IPvAnyAddress, ...] = Field(default=(), max_length=32)
    device_type: DeviceType
    vendor: EventVendor | None = None
    model: Annotated[Name, Field(max_length=120)] | None = None
    location: Annotated[Name, Field(max_length=120)] | None = None
    description: Annotated[str, Field(max_length=1000, pattern=r"^[^\x00]*$")] | None = None
    enabled: bool = True
    expected_interval_seconds: Annotated[int, Field(ge=60, le=604800)] | None = None

    @field_validator("source_addresses")
    @classmethod
    def unique_addresses(cls, values: tuple[IPvAnyAddress, ...]) -> tuple[IPvAnyAddress, ...]:
        if len(values) != len(set(values)):
            raise ValueError("Source addresses must be unique")
        return values


class DevicePatch(InputModel):
    name: Name | None = None
    hostname: str | None = Field(default=None, max_length=253)
    management_ip: IPvAnyAddress | None = None
    source_addresses: tuple[IPvAnyAddress, ...] | None = Field(default=None, max_length=32)
    device_type: DeviceType | None = None
    vendor: EventVendor | None = None
    model: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool | None = None
    expected_interval_seconds: Annotated[int, Field(ge=60, le=604800)] | None = None


class DeviceRecord(DeviceCreate):
    device_id: UUID
    status: DeviceStatus
    last_seen: AwareDatetime | None
    created_at: AwareDatetime
    updated_at: AwareDatetime


class DeviceActivity(DeviceRecord):
    event_count: int
    first_event_at: AwareDatetime | None
    last_event_at: AwareDatetime | None


class Page[T](BaseModel):
    items: list[T]
    page: int
    page_size: int
    total: int


class IndexedEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: EventId
    event_timestamp: AwareDatetime
    received_at: AwareDatetime
    ingested_at: AwareDatetime | None = None
    device_id: UUID | None
    device_name: str | None
    collector_ip: IPvAnyAddress | None
    source_ip: IPvAnyAddress | None
    vendor: EventVendor
    severity: EventSeverity
    event_type: EventType
    category: Category
    message: str
    parser_name: str


class EventDetail(BaseModel):
    event: IndexedEvent | None
    event_id: EventId
    parsing_status: Literal["parsed"] = "parsed"
    correlation_status: Literal["correlated", "unmatched", "unknown"]
    related_incident_ids: list[str]
    facility: int | None = None
    raw_message: str | None = None
    payload_status: Literal["available", "unavailable"]
    metadata: dict[str, object]


class EventRelations(BaseModel):
    incident_ids: list[str]
    related_event_ids: list[EventId]


class AuditRecord(BaseModel):
    audit_id: int
    timestamp: AwareDatetime
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    request_id: UUID | None
    outcome: Literal["success", "failure"]
    metadata: dict[str, object]


class TopologyNode(BaseModel):
    id: str
    name: str
    device_type: DeviceType
    vendor: EventVendor | None = None
    management_ip: IPvAnyAddress | None = None
    status: DeviceStatus = "unknown"
    last_seen: AwareDatetime | None = None
    active_incident_count: int = 0
    severity_summary: dict[str, int] = Field(default_factory=dict)


class LinkEndpoint(BaseModel):
    node_id: str
    router_id: str
    interface_name: str | None = None
    neighbor_state: OspfNeighborState | None = None


class TopologyLink(BaseModel):
    id: str
    source: str
    target: str | None = None
    kind: Literal["configured", "observed", "unmapped"]
    link_type: Literal["adjacency", "physical", "segment"] = "adjacency"
    protocol: Literal["ospf"] | None = "ospf"
    area: str | None = None
    peer_router_id: str | None = None
    source_interface: str | None = None
    target_interface: str | None = None
    status: Literal["up", "down", "transitioning", "unknown"] = "unknown"
    last_observed_at: AwareDatetime | None = None
    endpoints: list[LinkEndpoint] = Field(default_factory=list)
    related_incident_ids: list[str] = Field(default_factory=list)
    related_event_ids: list[EventId] = Field(default_factory=list)


class TopologyGraph(BaseModel):
    nodes: list[TopologyNode]
    links: list[TopologyLink]
    truncated: bool = False


class TrendPoint(BaseModel):
    timestamp: AwareDatetime
    count: int


class DashboardSummary(BaseModel):
    start: AwareDatetime
    end: AwareDatetime
    coverage_start: AwareDatetime | None
    total_events: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]
    active_incidents: int
    resolved_incidents: int
    critical_incidents: int
    high_incidents: int
    mean_resolution_seconds: float | None
    registered_devices: int
    device_status: dict[str, int]
    links: list[TopologyLink]
    link_availability: None = None
    events_per_second: float
    trend: list[TrendPoint]
    ingestion_trend: list[TrendPoint]
    significant_events: list[IndexedEvent]
    last_ingested_at: AwareDatetime | None


class GrafanaLink(BaseModel):
    url: str
