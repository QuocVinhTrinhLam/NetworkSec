"""Declarative rules shared by test evaluation and durable correlation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator

from app.schemas.backend import Category, InputModel, Name
from app.schemas.correlation import CorrelationConfig, RuleId
from app.schemas.event import EventSeverity, EventType, EventVendor, NormalizedEvent
from app.services.correlation import _event_window

GroupBy = Literal["device_name", "interface_name", "source_ip", "vendor"]


class RuleDefinition(InputModel):
    name: Name
    description: str = Field(default="", max_length=1000, pattern=r"^[^\x00]*$")
    priority: Annotated[int, Field(ge=0, le=1000)] = 100
    severity: EventSeverity
    category: Category
    event_types: Annotated[tuple[EventType, ...], Field(min_length=1, max_length=10)]
    recovery_types: Annotated[tuple[EventType, ...], Field(max_length=10)] = ()
    vendors: Annotated[tuple[EventVendor, ...], Field(max_length=3)] = ()
    group_by: Annotated[tuple[GroupBy, ...], Field(min_length=1, max_length=4)]
    threshold: Annotated[int, Field(ge=1, le=1000)] = 1
    window_seconds: Annotated[int, Field(ge=1, le=86400)] = 60
    dedup_seconds: Annotated[int, Field(ge=0, le=86400)] = 0

    @model_validator(mode="after")
    def validate_values(self) -> RuleDefinition:
        types = self.event_types + self.recovery_types
        if any(len(set(values)) != len(values) for values in (types, self.group_by, self.vendors)):
            raise ValueError("Rule values must be unique")
        if any(kind.value.startswith("routing_neighbor_") for kind in types):
            raise ValueError("OSPF neighbor transitions use the built-in adjacency policy")
        if self.dedup_seconds > self.window_seconds:
            raise ValueError("Deduplication window cannot exceed the aggregation window")
        return self

    def activation_error(self, config: CorrelationConfig) -> str | None:
        event_types = self.event_types + self.recovery_types
        if EventType.PORT_FLAP in event_types:
            return "port_flap has no verified parser or data source"
        owned = {kind for rule in config.rules if rule.enabled for kind in rule.event_types}
        if not owned.isdisjoint(event_types):
            return "An enabled built-in rule already owns one or more event types"
        return None


class RuleCreate(InputModel):
    id: RuleId
    enabled: bool = False
    definition: RuleDefinition


class RulePatch(InputModel):
    enabled: bool | None = None
    definition: RuleDefinition | None = None

    @model_validator(mode="after")
    def validate_patch(self) -> RulePatch:
        if self.enabled is None and self.definition is None:
            raise ValueError("Supply a rule definition or enabled state")
        return self


class RuleRecord(RuleCreate):
    revision: int


class RuleTest(InputModel):
    events: Annotated[list[NormalizedEvent], Field(max_length=100)]


class RuleOutcome(BaseModel):
    aggregate_id: str
    matching_events: int
    threshold_met: bool
    recovered: bool


@dataclass(frozen=True, slots=True)
class RuleMatch:
    aggregate_id: str
    start: datetime
    end: datetime
    group: dict[str, str]
    recovery: bool
    dedup_key: str


def _key(*parts: object) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def match_rule(
    rule: RuleRecord, event: NormalizedEvent, device_identity: str | None
) -> RuleMatch | None:
    definition = rule.definition
    kind = event.event_type
    if kind not in definition.event_types and kind not in definition.recovery_types:
        return None
    if definition.vendors and event.vendor not in definition.vendors:
        return None
    group_values = {
        "device_name": device_identity,
        "interface_name": event.interface_name,
        "source_ip": str(event.source_ip) if event.source_ip is not None else None,
        "vendor": event.vendor.value,
    }
    group: dict[str, str] = {}
    for name in definition.group_by:
        if (value := group_values[name]) is None:
            return None
        group[name] = value
    start, end = _event_window(event.timestamp, definition.window_seconds)
    aggregate = _key(rule.id, rule.revision, group, start.isoformat())
    dedup = event.event_id
    if definition.dedup_seconds:
        elapsed = (event.timestamp - start).total_seconds()
        dedup = _key(kind.value, event.message, int(elapsed // definition.dedup_seconds))
    return RuleMatch(aggregate, start, end, group, kind in definition.recovery_types, dedup)


def test_rule(rule: RuleRecord, events: list[NormalizedEvent]) -> list[RuleOutcome]:
    groups: dict[str, list[tuple[RuleMatch, NormalizedEvent]]] = {}
    for event in {item.event_id: item for item in events}.values():
        if match := match_rule(rule, event, event.device_name):
            groups.setdefault(match.aggregate_id, []).append((match, event))
    results = []
    for identifier, observations in sorted(groups.items()):
        failures = [
            (match.dedup_key, event.timestamp)
            for match, event in observations
            if not match.recovery
        ]
        count = len({key for key, _ in failures})
        opened = count >= rule.definition.threshold
        recovered = opened and any(
            match.recovery and event.timestamp > max(at for _, at in failures)
            for match, event in observations
        )
        results.append(
            RuleOutcome(
                aggregate_id=identifier,
                matching_events=count,
                threshold_met=opened,
                recovered=recovered,
            )
        )
    return results
