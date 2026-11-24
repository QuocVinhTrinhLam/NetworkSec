import json
import re
from pathlib import Path

import yaml

from app.schemas.event import EventType

GRAFANA = Path("infra/grafana")
EXISTING_LABELS = {"job", "schema_version", "event_type", "severity", "vendor"}


def test_ospf_dashboard_reuses_provisioning_and_existing_stream_labels() -> None:
    dashboards = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((GRAFANA / "dashboards").glob("*.json"))
    ]
    assert len({dashboard["uid"] for dashboard in dashboards}) == len(dashboards)
    provider = yaml.safe_load(
        (GRAFANA / "provisioning/dashboards/network-events.yaml").read_text(encoding="utf-8")
    )["providers"][0]
    datasource = yaml.safe_load(
        (GRAFANA / "provisioning/datasources/loki.yaml").read_text(encoding="utf-8")
    )["datasources"][0]
    compose = yaml.safe_load(Path("compose.yaml").read_text(encoding="utf-8"))
    grafana = compose["services"]["grafana"]
    grafana_mounts = grafana["volumes"]
    for directory in ("dashboards", "datasources"):
        source = f"./infra/grafana/provisioning/{directory}"
        target = f"/etc/grafana/provisioning/{directory}"
        assert f"{source}:{target}:ro" in grafana_mounts
    assert all(mount.split(":")[1] != "/etc/grafana/provisioning" for mount in grafana_mounts)
    assert grafana["environment"]["GF_PLUGINS_PREINSTALL_DISABLED"] == "true"
    assert f"./infra/grafana/dashboards:{provider['options']['path']}:ro" in grafana_mounts
    assert provider["options"]["path"] == "/var/lib/grafana/dashboards"
    assert datasource["type"] == "loki" and datasource["url"] == "http://loki:3100"
    by_uid = {dashboard["uid"]: dashboard for dashboard in dashboards}
    primary = by_uid["network-event-operations"]
    ospf = by_uid["network-ospf-observability"]
    assert by_uid["network-event-kpis"]["panels"]
    assert primary["uid"] == "network-event-operations"
    assert [panel["id"] for panel in primary["panels"]] == [1, 2, 3]
    assert ospf["uid"] == "network-ospf-observability"
    assert len({panel["id"] for panel in ospf["panels"]}) == len(ospf["panels"]) == 6
    for panel in ospf["panels"]:
        assert panel["datasource"] == {"type": "loki", "uid": datasource["uid"]}
        for target in panel["targets"]:
            selector = re.search(r"\{([^{}]+)\}", target["expr"])
            assert selector is not None
            assert 'job="network-events"' in selector[1]
            labels = set(re.findall(r"(\w+)\s*(?:=~|=)", selector[1]))
            assert labels <= EXISTING_LABELS
            assert "schema_version" not in labels
    for event in (
        EventType.ROUTING_NEIGHBOR_DOWN,
        EventType.ROUTING_NEIGHBOR_UP,
        EventType.ROUTING_NEIGHBOR_STATE_CHANGE,
    ):
        assert event.value in primary["templating"]["list"][1]["query"].split(",")
    assert "json device_name=" in ospf["panels"][4]["targets"][0]["expr"]
    assert "topk(15" in ospf["panels"][4]["targets"][0]["expr"]
