from pathlib import Path

from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.normalizer import normalize_alert

ROOT = Path(__file__).resolve().parent.parent


def test_normalizes_wazuh_alert_and_matches_catalog() -> None:
    mapper = SeverityMapper.from_file(ROOT / "config" / "severity.yaml")
    catalog = RulesCatalog.from_file(ROOT / "config" / "rules_catalog.yaml")
    document = {
        "@timestamp": "2026-10-25T09:30:00Z",
        "agent": {"name": "edge-pfsense"},
        "decoder": {"name": "pfsense"},
        "rule": {
            "id": "100201",
            "level": 10,
            "description": "Port scan detected",
            "groups": ["port_scan"],
            "mitre": {"id": ["T1046"], "technique": ["Network Service Discovery"]},
        },
        "data": {"srcip": "203.0.113.5", "dstip": "10.0.10.20"},
        "full_log": "blocked scan",
    }

    alert = normalize_alert(document, mapper, catalog, "source-document-id")
    replayed = normalize_alert(document, mapper, catalog, "different-source-document-id")

    assert alert.id == replayed.id
    assert len(alert.id) == 64
    assert alert.device_type == "firewall"
    assert alert.source_ip == "203.0.113.5"
    assert alert.severity == "high"
    assert alert.use_case_id == "port-scan"
    assert alert.mitre_id == "T1046"


def test_severity_mapping_boundaries() -> None:
    mapper = SeverityMapper.from_file(ROOT / "config" / "severity.yaml")
    assert mapper.map(0) == "low"
    assert mapper.map(5) == "medium"
    assert mapper.map(12) == "high"
    assert mapper.map(13) == "critical"
    assert mapper.map(99) == "critical"


def test_attacker_controlled_html_remains_plain_data() -> None:
    mapper = SeverityMapper.from_file(ROOT / "config" / "severity.yaml")
    catalog = RulesCatalog.from_file(ROOT / "config" / "rules_catalog.yaml")
    alert = normalize_alert(
        {
            "rule": {"id": "1", "level": 5, "description": "<script>alert(1)</script>"},
            "full_log": "<img src=x onerror=alert(1)>",
        },
        mapper,
        catalog,
    )
    assert alert.rule_description == "<script>alert(1)</script>"
    assert alert.raw_log == "<img src=x onerror=alert(1)>"
