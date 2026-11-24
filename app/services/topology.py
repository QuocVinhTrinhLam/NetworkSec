"""Build a graph from operator inventory and observed OSPF evidence."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, model_validator

from app.schemas.backend import (
    DeviceType,
    InputModel,
    LinkEndpoint,
    Name,
    TopologyGraph,
    TopologyLink,
    TopologyNode,
)
from app.schemas.correlation import OspfAdjacencyKey, OspfCorrelationConfig
from app.schemas.event import EventVendor, OspfNeighborState
from app.services.ospf_correlation import ospf_adjacency_id
from app.storage.backend import PostgresBackendStorage

MAX_GRAPH_ITEMS = 1000


class ConfiguredNode(InputModel):
    name: Name
    device_type: DeviceType
    vendor: EventVendor | None = None


class ConfiguredLink(InputModel):
    id: Name
    source: Name
    target: Name
    link_type: Literal["physical", "segment"]
    source_interface: Name | None = None
    target_interface: Name | None = None


class TopologyInventory(InputModel):
    nodes: Annotated[list[ConfiguredNode], Field(max_length=MAX_GRAPH_ITEMS)] = Field(
        default_factory=list
    )
    links: Annotated[list[ConfiguredLink], Field(max_length=MAX_GRAPH_ITEMS)] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def validate_graph(self) -> TopologyInventory:
        nodes = {node.name.casefold() for node in self.nodes}
        if len(nodes) != len(self.nodes) or len({link.id for link in self.links}) != len(
            self.links
        ):
            raise ValueError("Configured topology identifiers must be unique")
        for link in self.links:
            endpoints = {link.source.casefold(), link.target.casefold()}
            if len(endpoints) != 2 or not endpoints <= nodes:
                raise ValueError("A configured link must connect two configured nodes")
        return self


def load_topology(path: Path | None) -> TopologyInventory:
    if path is None:
        return TopologyInventory()
    return TopologyInventory.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _identity(namespace: str, parts: tuple[object, ...]) -> str:
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()
    return f"{namespace}:{digest}"


def build_topology(
    storage: PostgresBackendStorage,
    ospf: OspfCorrelationConfig | None,
    inventory: TopologyInventory,
    *,
    include_addresses: bool,
) -> TopologyGraph:
    devices = storage.devices(1, MAX_GRAPH_ITEMS)
    observed, incidents, counts = storage.topology_evidence(ospf.scope if ospf else "")
    by_node: dict[str, dict[str, int]] = defaultdict(dict)
    for row in counts:
        by_node[str(row["device_id"])][row["severity"]] = row["incidents"]

    nodes: dict[str, TopologyNode] = {}
    by_name: dict[str, str] = {}

    def inventory_node(
        name: str, kind: DeviceType = "router", vendor: EventVendor | None = None
    ) -> str:
        key = name.casefold()
        if key not in by_name:
            identifier = _identity("inventory", (key,))
            nodes[identifier] = TopologyNode(
                id=identifier, name=name, device_type=kind, vendor=vendor
            )
            by_name[key] = identifier
        return by_name[key]

    for device in devices.items:
        identifier = str(device.device_id)
        distribution = by_node[identifier]
        nodes[identifier] = TopologyNode(
            id=identifier,
            name=device.name,
            device_type=device.device_type,
            vendor=device.vendor,
            management_ip=device.management_ip if include_addresses else None,
            status=device.status,
            last_seen=device.last_seen,
            active_incident_count=sum(distribution.values()),
            severity_summary=distribution,
        )
        by_name[device.name.casefold()] = identifier
    for node in inventory.nodes:
        inventory_node(node.name, node.device_type, node.vendor)
    links = [
        TopologyLink(
            id=f"configured:{link.id}",
            kind="configured",
            protocol=None,
            link_type=link.link_type,
            source=inventory_node(link.source),
            target=inventory_node(link.target),
            source_interface=link.source_interface,
            target_interface=link.target_interface,
        )
        for link in inventory.links
    ]

    observations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observed[:MAX_GRAPH_ITEMS]:
        if row["link_id"] is not None:
            observations[row["adjacency_id"]].append(row)
    by_adjacency = {row["adjacency_id"]: row for row in incidents}
    matched = set()
    if ospf:
        for link in ospf.links:
            first, second = link.endpoints
            identifier = ospf_adjacency_id(
                OspfAdjacencyKey(
                    scope=ospf.scope,
                    area=link.area,
                    router_ids=tuple(sorted((first.router_id, second.router_id))),
                    link_id=link.id,
                )
            )
            matched.add(identifier)
            rows = observations[identifier]
            support = by_adjacency.get(identifier, {})
            endpoints = []
            for endpoint in link.endpoints:
                reporter = str(endpoint.router_id)
                state = next(
                    (
                        row["state"]
                        for row in rows
                        if row["local_router_id"] == reporter and row["reliable"]
                    ),
                    None,
                )
                endpoints.append(
                    LinkEndpoint(
                        node_id=inventory_node(endpoint.device_name),
                        router_id=reporter,
                        interface_name=endpoint.interface_name,
                        neighbor_state=state,
                    )
                )
            statuses = {
                endpoint.neighbor_state for endpoint in endpoints if endpoint.neighbor_state
            }
            status: Literal["up", "down", "transitioning", "unknown"] = "unknown"
            if support.get("has_outage") or OspfNeighborState.DOWN in statuses:
                status = "down"
            elif statuses - {OspfNeighborState.FULL}:
                status = "transitioning"
            elif len(statuses) == 1 and all(endpoint.neighbor_state for endpoint in endpoints):
                status = "up"
            links.append(
                TopologyLink(
                    id=identifier,
                    kind="observed" if rows or support else "configured",
                    source=endpoints[0].node_id,
                    target=endpoints[1].node_id,
                    area=str(link.area),
                    endpoints=endpoints,
                    status=status,
                    last_observed_at=max((row["last_observed_at"] for row in rows), default=None),
                    related_event_ids=[row["event_id"] for row in rows],
                    related_incident_ids=support.get("ids", []),
                )
            )

    for row in observed[:MAX_GRAPH_ITEMS]:
        if row["adjacency_id"] in matched:
            continue
        identifier = _identity(
            "unmapped",
            (
                row["adjacency_id"],
                row["scope"],
                row["device_name"],
                row["interface_name"],
                row["area"],
                row["local_router_id"],
                row["peer_router_id"],
                row["collector"],
            ),
        )
        source = str(row["device_id"])
        if source not in nodes:
            source = _identity(
                "reporter", (row["device_name"], row["collector"], row["local_router_id"])
            )
            nodes.setdefault(
                source,
                TopologyNode(
                    id=source,
                    name=row["device_name"] or "(unknown reporter)",
                    device_type="router",
                ),
            )
        local = []
        if row["local_router_id"]:
            local.append(
                LinkEndpoint(
                    node_id=source,
                    router_id=row["local_router_id"],
                    interface_name=row["interface_name"],
                    neighbor_state=row["state"] if row["reliable"] else None,
                )
            )
        links.append(
            TopologyLink(
                id=identifier,
                kind="unmapped",
                source=source,
                peer_router_id=row["peer_router_id"],
                area=row["area"],
                endpoints=local,
                last_observed_at=row["last_observed_at"],
                related_event_ids=[row["event_id"]],
                related_incident_ids=by_adjacency.get(row["adjacency_id"], {}).get("ids", []),
            )
        )
    # Keep every referenced node, including a configured endpoint without telemetry.
    return TopologyGraph(
        nodes=list(nodes.values()),
        links=links[:MAX_GRAPH_ITEMS],
        truncated=devices.total > MAX_GRAPH_ITEMS
        or any(len(items) > MAX_GRAPH_ITEMS for items in (observed, incidents, links)),
    )
