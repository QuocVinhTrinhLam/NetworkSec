"""Versioned contracts for deterministic event correlation."""

from __future__ import annotations

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

from app.schemas.event import EventSeverity, EventType, NormalizedEvent

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


class CorrelationConfig(BaseModel):
    """Versioned top-level correlation configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    rules: Annotated[tuple[CorrelationRule, ...], Field(min_length=1)]

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


class CorrelationResult(BaseModel):
    """Outcome returned for every normalized event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matched: StrictBool
    duplicate: StrictBool = False
    reason: StrictStr | None = None
    alert: AggregatedAlert | None = None


class NotificationClaim(BaseModel):
    """Atomic cooldown decision for a downstream notification worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: StrictBool
    aggregate_id: StrictStr
    claimed_at: AwareDatetime | None = None
    next_allowed_at: AwareDatetime | None = None
