from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TOPOLOGY_PATH = Path("gns3/topology/Network-Security-Monitoring-Lab.gns3")


def _topology() -> dict[str, Any]:
    return json.loads(TOPOLOGY_PATH.read_text(encoding="utf-8"))


def test_phase7_audit_matches_current_topology_metadata() -> None:
    project = _topology()
    topology = project["topology"]
    names = {node["name"] for node in topology["nodes"]}

    assert project["version"] == "2.2.61"
    assert len(topology["nodes"]) == 8
    assert len(topology["links"]) == 7
    assert names == {
        "NAT1",
        "PC1",
        "PC2",
        "PC3",
        "Switch1",
        "MikroTikCHR7.24.6-1",
        "pfSense-Firewall-1",
        "webterm-1",
    }


def test_builtin_switch_and_webterm_link_are_documented_without_mutation() -> None:
    topology = _topology()["topology"]
    nodes = {node["node_id"]: node for node in topology["nodes"]}
    switch = next(node for node in topology["nodes"] if node["name"] == "Switch1")
    webterm = next(node for node in topology["nodes"] if node["name"] == "webterm-1")
    port_four = next(
        port for port in switch["properties"]["ports_mapping"] if port["port_number"] == 4
    )
    peers = {
        (nodes[endpoint["node_id"]]["name"], endpoint["port_number"])
        for link in topology["links"]
        for endpoint in link["nodes"]
        if any(item["node_id"] == webterm["node_id"] for item in link["nodes"])
    }

    assert switch["node_type"] == "ethernet_switch"
    assert port_four == {
        "name": "Ethernet4",
        "port_number": 4,
        "type": "access",
        "vlan": 10,
    }
    assert peers == {("Switch1", 4), ("webterm-1", 0)}


def test_phase7_results_do_not_claim_unperformed_live_delivery() -> None:
    results = Path("gns3/docs/phase7-test-results.md").read_text(encoding="utf-8")

    assert "## Live device results" in results
    assert "## Replayed results" in results
    assert "## Synthetic results" in results
    assert "CHR -> Ubuntu UDP 5514 | NOT RUN" in results
    assert "Link down/up event | NOT RUN" in results
