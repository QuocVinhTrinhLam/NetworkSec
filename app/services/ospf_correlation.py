"""Resolve OSPF adjacency identity and replay its technical lifecycle."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address

from app.schemas.correlation import (
    OspfAdjacencyKey,
    OspfCorrelationConfig,
    OspfCorrelationSnapshot,
    OspfIncident,
    OspfIncidentEvidence,
    OspfReporterState,
)
from app.schemas.event import NormalizedEvent, OspfNeighborState
from app.services.backend import transport_address


@dataclass(frozen=True, slots=True)
class OspfIdentity:
    adjacency: OspfAdjacencyKey
    reporter: IPv4Address


def resolve_ospf_identity(
    event: NormalizedEvent, config: OspfCorrelationConfig, collector_source: str | None = None
) -> OspfIdentity:
    peer = event.neighbor_router_id
    if event.routing_protocol != "ospf" or peer is None:
        raise ValueError("missing OSPF protocol or peer router ID")
    if not event.device_name or not event.interface_name:
        raise ValueError("missing OSPF reporting device or interface")

    source = (event.device_name, event.interface_name)
    collector_ip = transport_address(collector_source)
    matches: list[OspfIdentity] = []
    configured_endpoint = False
    for link in config.links:
        first, second = link.endpoints
        for local, remote in ((first, second), (second, first)):
            if (local.device_name, local.interface_name) != source:
                continue
            configured_endpoint = True
            if (
                remote.router_id != peer
                or event.local_router_id not in (None, local.router_id)
                or event.ospf_area not in (None, link.area)
                or (
                    local.source_addresses
                    and all(str(address) != collector_ip for address in local.source_addresses)
                )
            ):
                continue
            matches.append(
                OspfIdentity(
                    OspfAdjacencyKey(
                        scope=config.scope,
                        area=link.area,
                        router_ids=_router_pair(local.router_id, peer),
                        link_id=link.id,
                    ),
                    local.router_id,
                )
            )
    if len(matches) == 1:
        return matches[0]
    if configured_endpoint:
        raise ValueError("OSPF reporting endpoint is ambiguous or conflicts with inventory")

    local_id, area = event.local_router_id, event.ospf_area
    if local_id is None or area is None:
        raise ValueError("missing OSPF area or local router ID; configure the reporting link")
    if local_id == peer:
        raise ValueError("OSPF local and peer router IDs must be distinct")
    return OspfIdentity(
        OspfAdjacencyKey(
            scope=config.scope,
            area=area,
            router_ids=_router_pair(local_id, peer),
            local_interface=source,
        ),
        local_id,
    )


def _router_pair(first: IPv4Address, second: IPv4Address) -> tuple[IPv4Address, IPv4Address]:
    return min(first, second), max(first, second)


def ospf_adjacency_id(adjacency: OspfAdjacencyKey) -> str:
    return hashlib.sha256(adjacency.model_dump_json().encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class OspfObservation:
    sequence: int
    event_id: str
    reporter: IPv4Address
    timestamp: datetime
    received_at: datetime
    state: OspfNeighborState
    clock_reliable: bool
    uncertain_until: datetime | None = None

    @property
    def ordering_at(self) -> datetime:
        return self.timestamp if self.clock_reliable else self.received_at


@dataclass(slots=True)
class _Outage:
    first_down_at: datetime
    anchor: OspfObservation
    reporters: dict[IPv4Address, OspfReporterState] = field(default_factory=dict)
    evidence: list[OspfIncidentEvidence] = field(default_factory=list)

    def record_down(self, observation: OspfObservation) -> None:
        if observation.clock_reliable and observation.sequence < self.anchor.sequence:
            self.anchor = observation
        previous = self.reporters.get(observation.reporter)
        uncertain_until = observation.uncertain_until
        if previous is not None and previous.uncertain_until is not None:
            uncertain_until = max(
                uncertain_until or observation.ordering_at, previous.uncertain_until
            )
        self.reporters[observation.reporter] = OspfReporterState(
            router_id=observation.reporter,
            last_down_at=observation.ordering_at,
            uncertain_until=uncertain_until,
        )
        self._record_evidence(observation)

    def record_full(self, observation: OspfObservation) -> bool:
        previous = self.reporters.get(observation.reporter)
        if previous is None or observation.timestamp <= previous.last_down_at:
            return False
        if (
            previous.uncertain_until is not None
            and observation.timestamp <= previous.uncertain_until
        ):
            return False
        self._record_evidence(observation)
        if previous.full_at is None:
            self.reporters[observation.reporter] = previous.model_copy(
                update={"full_at": observation.timestamp}
            )
        return all(side.full_at is not None for side in self.reporters.values())

    def _record_evidence(self, observation: OspfObservation) -> None:
        self.evidence.append(
            OspfIncidentEvidence(
                event_id=observation.event_id,
                timestamp=observation.timestamp,
                observed_at=observation.ordering_at,
                reporter_router_id=observation.reporter,
                event_type=observation.state.classification[0],
            )
        )

    def snapshot(self, adjacency_id: str, recovered_at: datetime | None = None) -> OspfIncident:
        incident_id = hashlib.sha256(f"{adjacency_id}:{self.anchor.event_id}".encode()).hexdigest()
        return OspfIncident(
            incident_id=incident_id,
            first_down_at=self.first_down_at,
            recovered_at=recovered_at,
            reporters=tuple(self.reporters[key] for key in sorted(self.reporters)),
            evidence=tuple(self.evidence),
        )


def project_ospf(
    adjacency: OspfAdjacencyKey,
    observations: list[OspfObservation],
) -> OspfCorrelationSnapshot:
    """Fold event time, guarding open outages against DOWN with an uncertain clock."""
    adjacency_id = ospf_adjacency_id(adjacency)
    timeline = sorted(
        (
            item
            for item in observations
            if item.clock_reliable or item.state is OspfNeighborState.DOWN
        ),
        key=lambda item: (
            item.ordering_at,
            item.state is not OspfNeighborState.DOWN,
            item.sequence,
        ),
    )
    incidents: list[OspfIncident] = []
    outage: _Outage | None = None
    for observation in timeline:
        if observation.state is OspfNeighborState.DOWN:
            if outage is None and observation.clock_reliable:
                outage = _Outage(observation.timestamp, observation)
            if outage is not None:
                outage.record_down(observation)
        elif outage is not None and outage.record_full(observation):
            incidents.append(outage.snapshot(adjacency_id, observation.timestamp))
            outage = None
    if outage is not None:
        incidents.append(outage.snapshot(adjacency_id))

    return OspfCorrelationSnapshot(
        adjacency_id=adjacency_id,
        adjacency=adjacency,
        revision=max((item.sequence for item in observations), default=0),
        incidents=tuple(incidents),
        unreliable_event_ids=tuple(
            item.event_id for item in observations if not item.clock_reliable
        ),
    )
