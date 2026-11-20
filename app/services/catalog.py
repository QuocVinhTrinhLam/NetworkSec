"""Load configurable severity thresholds and detection use cases."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RULE_LEVELS = range(16)


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return loaded


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("Expected a list of strings")
    return tuple(str(item) for item in value)


@dataclass(frozen=True, slots=True)
class SeverityMapper:
    """Map every supported numeric rule level to a named severity."""

    levels: tuple[str, ...]

    @classmethod
    def from_file(cls, path: Path) -> SeverityMapper:
        document = _load_yaml(path)
        explicit = document.get("rule_level_to_severity")
        if explicit is not None:
            if not isinstance(explicit, dict):
                raise ValueError("rule_level_to_severity must be a mapping")
            level_map = {int(level): str(severity) for level, severity in explicit.items()}
            missing = set(RULE_LEVELS).difference(level_map)
            extra = set(level_map).difference(RULE_LEVELS)
            if missing or extra:
                raise ValueError("severity map must define exactly rule levels 0 through 15")
            invalid = set(level_map.values()).difference(SEVERITY_ORDER)
            if invalid:
                raise ValueError(f"Unknown severities: {', '.join(sorted(invalid))}")
            return cls(tuple(level_map[level] for level in RULE_LEVELS))

        # Backward compatibility for the original range-based severity.yaml.
        ranges = document.get("severity", {})
        if not isinstance(ranges, dict) or set(ranges) != set(SEVERITY_ORDER):
            raise ValueError("severity config must define low, medium, high and critical")
        legacy_level_map: dict[int, str] = {}
        for severity, bounds in ranges.items():
            if not isinstance(bounds, dict):
                raise ValueError(f"Invalid bounds for severity {severity}")
            lower, upper = int(bounds["min"]), int(bounds["max"])
            for level in range(lower, upper + 1):
                if level in legacy_level_map:
                    raise ValueError(f"Rule level {level} is mapped more than once")
                legacy_level_map[level] = str(severity)
        if set(legacy_level_map) != set(RULE_LEVELS):
            raise ValueError("severity ranges must cover exactly rule levels 0 through 15")
        return cls(tuple(legacy_level_map[level] for level in RULE_LEVELS))

    @property
    def ranges(self) -> dict[str, tuple[int, int]]:
        """Return the legacy range view for callers that still inspect it."""
        return {
            severity: (
                min(level for level, value in enumerate(self.levels) if value == severity),
                max(level for level, value in enumerate(self.levels) if value == severity),
            )
            for severity in SEVERITY_ORDER
        }

    def map(self, level: int) -> str:
        if level < 0:
            return "low"
        if level >= len(self.levels):
            return "critical"
        return self.levels[level]

    @staticmethod
    def allows(severity: str, minimum: str) -> bool:
        return SEVERITY_ORDER.get(severity, -1) >= SEVERITY_ORDER.get(minimum, 1)


@dataclass(frozen=True, slots=True)
class MitreMapping:
    id: str
    name: str
    tactic: str


@dataclass(frozen=True, slots=True)
class RuleCatalogEntry:
    id: str
    name: str
    description: str
    rule_ids: frozenset[str]
    groups: frozenset[str]
    default_severity: str
    mitre: tuple[MitreMapping, ...]
    recommended_responses: tuple[tuple[str, str], ...]

    @property
    def severity(self) -> str:
        """Compatibility alias used by the existing normalizer."""
        return self.default_severity

    @property
    def recommended_response(self) -> str:
        """Compatibility alias; English remains the pipeline default."""
        return self.recommended_response_for("en")

    def recommended_response_for(self, language: str) -> str:
        responses = dict(self.recommended_responses)
        return responses.get(language) or responses.get("en") or next(iter(responses.values()), "")


class RulesCatalog:
    """Resolve normalized alerts to an immutable detection use-case catalog."""

    def __init__(self, entries: Iterable[RuleCatalogEntry]) -> None:
        self.entries = tuple(entries)
        ids = [entry.id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("rules catalog contains duplicate IDs")

    @classmethod
    def from_file(cls, path: Path) -> RulesCatalog:
        document = _load_yaml(path)
        raw_entries = document.get("use_cases", [])
        if not isinstance(raw_entries, list):
            raise ValueError("use_cases must be a list")
        entries: list[RuleCatalogEntry] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                raise ValueError("each use case must be a mapping")
            match = item.get("match", {})
            if not isinstance(match, dict):
                raise ValueError(f"match must be a mapping for {item.get('id', 'unknown')}")
            severity = str(item.get("default_severity", item.get("severity", "")))
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"invalid default severity for {item.get('id', 'unknown')}")

            raw_responses = item.get("recommended_response", {})
            responses: tuple[tuple[str, str], ...]
            if isinstance(raw_responses, str):
                responses = (("en", raw_responses),)
            elif isinstance(raw_responses, dict):
                responses = tuple(
                    (str(language), str(response))
                    for language, response in raw_responses.items()
                    if response
                )
            else:
                raise ValueError(
                    "recommended_response must be text or a mapping for "
                    f"{item.get('id', 'unknown')}"
                )
            if not responses:
                raise ValueError(
                    f"recommended_response is required for {item.get('id', 'unknown')}"
                )

            raw_mitre = item.get("mitre", [])
            if not isinstance(raw_mitre, list):
                raise ValueError(f"mitre must be a list for {item.get('id', 'unknown')}")
            mitre = tuple(
                MitreMapping(
                    id=str(mapping["id"]),
                    name=str(mapping["name"]),
                    tactic=str(mapping["tactic"]),
                )
                for mapping in raw_mitre
                if isinstance(mapping, dict)
            )

            entries.append(
                RuleCatalogEntry(
                    id=str(item["id"]),
                    name=str(item["name"]),
                    description=str(item.get("description", item["name"])),
                    rule_ids=frozenset(
                        _string_tuple(match.get("rule_ids", item.get("rule_ids", [])))
                    ),
                    groups=frozenset(_string_tuple(match.get("groups", item.get("groups", [])))),
                    default_severity=severity,
                    mitre=mitre,
                    recommended_responses=responses,
                )
            )
        return cls(entries)

    def get(self, catalog_id: str) -> RuleCatalogEntry | None:
        return next((entry for entry in self.entries if entry.id == catalog_id), None)

    def match(self, rule_id: str, groups: list[str]) -> RuleCatalogEntry | None:
        # An explicit rule ID is more precise than a possibly shared rule group.
        explicit = next((entry for entry in self.entries if rule_id in entry.rule_ids), None)
        if explicit:
            return explicit
        observed_groups = set(groups)
        return next(
            (entry for entry in self.entries if observed_groups.intersection(entry.groups)),
            None,
        )
