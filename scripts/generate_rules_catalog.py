"""Generate the human-readable rules catalog from its YAML source."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def generate() -> str:
    source = ROOT / "config" / "rules_catalog.yaml"
    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    lines = [
        "# Rules Catalog",
        "",
        "Generated from `config/rules_catalog.yaml`. Edit the YAML, then rerun "
        "`python scripts/generate_rules_catalog.py`.",
        "",
    ]
    for entry in document["use_cases"]:
        match = entry["match"]
        mitre = ", ".join(
            f"`{item['id']}` {item['name']} ({item['tactic']})" for item in entry["mitre"]
        )
        rules = ", ".join(f"`{item}`" for item in match.get("rule_ids", [])) or "—"
        groups = ", ".join(f"`{item}`" for item in match.get("groups", [])) or "—"
        response = entry["recommended_response"]
        lines.extend(
            [
                f"## {entry['name']} (`{entry['id']}`)",
                "",
                entry["description"],
                "",
                f"- Default severity: **{entry['default_severity']}**",
                f"- Rule IDs: {rules}",
                f"- Groups: {groups}",
                f"- MITRE ATT&CK: {mitre or '—'}",
                f"- Recommended (EN): {response['en']}",
                f"- Khuyến nghị (VI): {response['vi']}",
                "",
            ]
        )
    return "\n".join(lines)


if __name__ == "__main__":
    output = ROOT / "docs" / "rules_catalog.md"
    output.write_text(generate(), encoding="utf-8")
    print(f"Generated {output.relative_to(ROOT)}")
