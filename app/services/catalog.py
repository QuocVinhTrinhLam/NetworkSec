"""Load configurable severity thresholds and detection use cases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return loaded


@dataclass(frozen=True, slots=True)
class SeverityMapper:
    """Map numeric Wazuh levels to named severities."""

    ranges: dict[str, tuple[int, int]]

    @classmethod
    def from_file(cls, path: Path) -> SeverityMapper:
        document = _load_yaml(path)
        ranges: dict[str, tuple[int, int]] = {}
        for name, bounds in document.get("severity", {}).items():
            ranges[name] = (int(bounds["min"]), int(bounds["max"]))
        if set(ranges) != set(SEVERITY_ORDER):
            raise ValueError("severity.yaml must define low, medium, high and critical")
        return cls(ranges)

    def map(self, level: int) -> str:
        for name in ("low", "medium", "high", "critical"):
            lower, upper = self.ranges[name]
            if lower <= level <= upper:
                return name
        return "critical" if level > 15 else "low"

    @staticmethod
    def allows(severity: str, minimum: str) -> bool:
        return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER.get(minimum, 1)


@dataclass(frozen=True, slots=True)
class RuleCatalogEntry:
    id: str
    name: str
    rule_ids: frozenset[str]
    groups: frozenset[str]
    severity: str
    recommended_response: str


class RulesCatalog:
    """Resolve normalized alerts to a capstone detection use case."""

    def __init__(self, entries: list[RuleCatalogEntry]) -> None:
        self.entries = entries

    @classmethod
    def from_file(cls, path: Path) -> RulesCatalog:
        document = _load_yaml(path)
        entries = [
            RuleCatalogEntry(
                id=str(item["id"]),
                name=str(item["name"]),
                rule_ids=frozenset(str(value) for value in item.get("rule_ids", [])),
                groups=frozenset(str(value) for value in item.get("groups", [])),
                severity=str(item["severity"]),
                recommended_response=str(item["recommended_response"]),
            )
            for item in document.get("use_cases", [])
        ]
        return cls(entries)

    def match(self, rule_id: str, groups: list[str]) -> RuleCatalogEntry | None:
        observed_groups = set(groups)
        for entry in self.entries:
            if rule_id in entry.rule_ids or observed_groups.intersection(entry.groups):
                return entry
        return None
