"""Versioned JSON contracts for the Phase 5 backend API."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, StrictStr

from app.schemas.correlation import OspfAdjacencyKey, OspfReporterState
from app.schemas.event import EventSeverity, EventType, NormalizedEvent


class AlertLifecycleStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertRecord(BaseModel):
    """Aggregated alert state returned by PostgreSQL."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    aggregate_id: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    rule_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    event_family: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    device_name: StrictStr | None = None
    interface_name: StrictStr | None = None
    event_types: tuple[EventType, ...]
    window_start: AwareDatetime
    window_end: AwareDatetime
    count: Annotated[StrictInt, Field(ge=1)]
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    severity: EventSeverity
    status: AlertLifecycleStatus
    acknowledged_by: StrictStr | None = None
    acknowledged_at: AwareDatetime | None = None
    status_changed_by: StrictStr | None = None
    status_changed_at: AwareDatetime
    note: StrictStr | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime


class EventPageResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: tuple[NormalizedEvent, ...]
    page_size: StrictInt
    next_cursor: StrictStr | None = None


class AlertPageResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: tuple[AlertRecord, ...]
    page: StrictInt
    page_size: StrictInt
    total: StrictInt


class AlertEventEvidence(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: StrictStr
    timestamp: AwareDatetime
    event_type: EventType | None
    reporter_router_id: IPv4Address | None
    is_current: bool
    source_ip: StrictStr | None


class AlertHistoryEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    previous_status: AlertLifecycleStatus | None
    status: AlertLifecycleStatus
    source: StrictStr
    actor: StrictStr | None
    note: StrictStr | None
    changed_at: AwareDatetime


class OspfEvidenceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    adjacency: OspfAdjacencyKey
    technical_recovered_at: AwareDatetime | None
    superseded_at: AwareDatetime | None
    reporters: tuple[OspfReporterState, ...]


class AlertEvidenceResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    alert_id: StrictStr
    event_refs: tuple[AlertEventEvidence, ...]
    history: tuple[AlertHistoryEntry, ...]
    ospf: OspfEvidenceSummary | None


class AlertAcknowledgementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: Annotated[StrictStr, Field(min_length=1, max_length=1000)] | None = None


class AlertStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertLifecycleStatus
    note: Annotated[StrictStr, Field(min_length=1, max_length=1000)] | None = None


class StorageHealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    loki: Literal["ready", "unavailable"]
    postgres: Literal["ready", "unavailable"]
    checked_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
