from pathlib import Path

import pytest

from app.services.catalog import RulesCatalog, SeverityMapper

ROOT = Path(__file__).resolve().parent.parent


def test_explicit_severity_map_covers_rule_levels() -> None:
    mapper = SeverityMapper.from_file(ROOT / "config" / "severity_map.yaml")

    assert [mapper.map(level) for level in range(16)] == [
        "low",
        "low",
        "low",
        "low",
        "low",
        "medium",
        "medium",
        "medium",
        "medium",
        "high",
        "high",
        "high",
        "high",
        "critical",
        "critical",
        "critical",
    ]
    assert mapper.map(-1) == "low"
    assert mapper.map(99) == "critical"
    assert mapper.ranges["high"] == (9, 12)


def test_severity_map_rejects_missing_levels(tmp_path: Path) -> None:
    incomplete = tmp_path / "severity_map.yaml"
    incomplete.write_text("rule_level_to_severity:\n  0: low\n", encoding="utf-8")

    with pytest.raises(ValueError, match="levels 0 through 15"):
        SeverityMapper.from_file(incomplete)


def test_catalog_covers_phase_one_use_cases_and_bilingual_responses() -> None:
    catalog = RulesCatalog.from_file(ROOT / "config" / "rules_catalog.yaml")
    expected_ids = {
        "port-scan",
        "network-brute-force",
        "admin-login-success",
        "admin-login-failure",
        "configuration-change",
        "interface-flapping",
        "arp-spoofing",
        "mac-flooding-port-security",
        "vlan-hopping",
        "syn-flood",
        "vpn-anomaly",
        "device-silent",
    }

    assert {entry.id for entry in catalog.entries} == expected_ids
    for entry in catalog.entries:
        assert entry.description
        assert entry.rule_ids
        assert entry.groups
        assert entry.default_severity in {"low", "medium", "high", "critical"}
        assert entry.mitre
        assert entry.recommended_response_for("en")
        assert entry.recommended_response_for("vi")


def test_catalog_lookup_prefers_rule_id_and_keeps_legacy_properties() -> None:
    catalog = RulesCatalog.from_file(ROOT / "config" / "rules_catalog.yaml")

    by_id = catalog.get("port-scan")
    assert by_id is not None
    assert by_id.severity == "high"
    assert by_id.recommended_response == by_id.recommended_response_for("en")
    assert by_id.mitre[0].id == "T1046"

    failed_login = catalog.match("100221", [])
    arp_spoofing = catalog.match("unknown", ["arp_poisoning"])
    assert failed_login is not None and failed_login.id == "admin-login-failure"
    assert arp_spoofing is not None and arp_spoofing.id == "arp-spoofing"
    assert catalog.match("unknown", ["not_a_real_group"]) is None
