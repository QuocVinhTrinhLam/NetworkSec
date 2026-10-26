"""Realistic replay, random and scripted mock alert source."""

from __future__ import annotations

import asyncio
import copy
import json
import random
from collections.abc import Awaitable, Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from app.adapters.base import BaseAdapter
from app.schemas.alert import Alert, AlertSource
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.normalizer import normalize_alert

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = ROOT / "fixtures" / "alerts.json"
DEFAULT_SEVERITY_MAP = ROOT / "config" / "severity_map.yaml"
DEFAULT_CATALOG = ROOT / "config" / "rules_catalog.yaml"

MockMode = Literal["replay", "random", "scenario"]
Sleep = Callable[[float], Awaitable[None]]

DEFAULT_SEVERITY_DISTRIBUTION: dict[str, float] = {
    "low": 0.10,
    "medium": 0.30,
    "high": 0.35,
    "critical": 0.25,
}

SCENARIOS = (
    "ssh_bruteforce",
    "port_scan",
    "syn_flood",
    "arp_spoof",
    "config_change",
    "device_silent",
)


def load_fixture_documents(path: Path = DEFAULT_FIXTURES) -> list[dict[str, Any]]:
    """Load fixture documents without trusting their shape."""
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"Mock fixtures must be a JSON list of objects: {path}")
    return [dict(item) for item in value]


def _aware_utc(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("Mock start time must include a timezone")
    return observed.astimezone(UTC)


def _timeline(end: datetime, count: int, duration_seconds: int) -> list[datetime]:
    if count <= 0:
        return []
    if count == 1:
        return [end]
    duration = max(1, duration_seconds)
    start = end - timedelta(seconds=duration)
    step = duration / (count - 1)
    return [start + timedelta(seconds=index * step) for index in range(count)]


class MockAdapter(BaseAdapter):
    """Emit canonical alerts from fixtures, randomized traffic or a scripted scenario."""

    def __init__(
        self,
        alerts: Iterable[Alert] | None = None,
        *,
        mode: MockMode = "replay",
        scenario: str | None = None,
        count: int = 100,
        duration_seconds: int = 60,
        rate_per_second: float = 0,
        severity_distribution: Mapping[str, float] | None = None,
        fixtures_path: Path = DEFAULT_FIXTURES,
        severity_map_path: Path = DEFAULT_SEVERITY_MAP,
        catalog_path: Path = DEFAULT_CATALOG,
        start_time: datetime | None = None,
        seed: int | None = None,
        batch_size: int = 1,
        sleeper: Sleep = asyncio.sleep,
    ) -> None:
        if mode not in {"replay", "random", "scenario"}:
            raise ValueError("Mock mode must be replay, random or scenario")
        if rate_per_second < 0:
            raise ValueError("Mock replay rate cannot be negative")
        if batch_size < 1:
            raise ValueError("Mock batch size must be at least one")
        if mode == "scenario" and scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario. Choose one of: {', '.join(SCENARIOS)}")

        self.mode = mode
        self.scenario = scenario
        self.rate_per_second = rate_per_second
        self.batch_size = batch_size
        self._sleeper = sleeper
        self._last_emit = False
        self._cursor = 0
        self._random = random.Random(seed)

        if alerts is not None:
            self._alerts = list(alerts)
            self.batch_size = max(1, len(self._alerts))
            return

        documents = load_fixture_documents(fixtures_path)
        mapper = SeverityMapper.from_file(severity_map_path)
        catalog = RulesCatalog.from_file(catalog_path)
        end = _aware_utc(start_time)
        distribution = self._validate_distribution(
            severity_distribution or DEFAULT_SEVERITY_DISTRIBUTION
        )

        if mode == "replay":
            selected = self._replay_documents(documents, end)
        elif mode == "random":
            selected = self._random_documents(
                documents,
                count=max(0, count),
                end=end,
                duration_seconds=max(1, duration_seconds),
                distribution=distribution,
                mapper=mapper,
                catalog=catalog,
            )
        else:
            selected = self._scenario_documents(
                documents,
                str(scenario),
                end=end,
                duration_seconds=max(1, duration_seconds),
            )

        self._alerts = [
            normalize_alert(document, mapper, catalog, source=AlertSource.MOCK)
            for document in selected
        ]

    @property
    def exhausted(self) -> bool:
        """Return whether every prepared alert has been emitted."""
        return self._cursor >= len(self._alerts)

    async def fetch_new_alerts(self) -> list[Alert]:
        """Return the next rate-limited batch of normalized mock alerts."""
        if self.exhausted:
            return []
        if self._last_emit and self.rate_per_second:
            await self._sleeper(1 / self.rate_per_second)
        stop = min(len(self._alerts), self._cursor + self.batch_size)
        batch = self._alerts[self._cursor : stop]
        self._cursor = stop
        self._last_emit = True
        return list(batch)

    @staticmethod
    def _validate_distribution(distribution: Mapping[str, float]) -> dict[str, float]:
        expected = {"low", "medium", "high", "critical"}
        if set(distribution) != expected:
            raise ValueError("Severity distribution must define low, medium, high and critical")
        weights = {key: float(value) for key, value in distribution.items()}
        if any(value < 0 for value in weights.values()) or sum(weights.values()) <= 0:
            raise ValueError("Severity distribution weights must be non-negative and not all zero")
        return weights

    @staticmethod
    def _with_timestamp(document: dict[str, Any], timestamp: datetime) -> dict[str, Any]:
        result = copy.deepcopy(document)
        result["@timestamp"] = timestamp.isoformat(timespec="milliseconds")
        return result

    def _replay_documents(
        self, documents: list[dict[str, Any]], end: datetime
    ) -> list[dict[str, Any]]:
        timeline = _timeline(end, len(documents), max(1, len(documents) - 1))
        return [
            self._with_timestamp(document, timestamp)
            for document, timestamp in zip(documents, timeline, strict=True)
        ]

    def _random_documents(
        self,
        documents: list[dict[str, Any]],
        *,
        count: int,
        end: datetime,
        duration_seconds: int,
        distribution: dict[str, float],
        mapper: SeverityMapper,
        catalog: RulesCatalog,
    ) -> list[dict[str, Any]]:
        pools: dict[str, list[dict[str, Any]]] = {
            "low": [],
            "medium": [],
            "high": [],
            "critical": [],
        }
        for document in documents:
            alert = normalize_alert(document, mapper, catalog, source=AlertSource.MOCK)
            pools[alert.severity.value].append(document)

        severities = list(distribution)
        weights = [distribution[value] for value in severities]
        result: list[dict[str, Any]] = []
        for timestamp in _timeline(end, count, duration_seconds):
            severity = self._random.choices(severities, weights=weights, k=1)[0]
            candidates = pools[severity]
            if candidates:
                document = copy.deepcopy(self._random.choice(candidates))
            else:
                document = copy.deepcopy(self._random.choice(documents))
                document["rule"] = {
                    "id": f"MOCK_{severity.upper()}",
                    "level": {"low": 2, "medium": 6, "high": 10, "critical": 14}[severity],
                    "description": f"Randomized {severity} severity network event",
                    "groups": ["mock_random"],
                }
            self._randomize_entities(document)
            result.append(self._with_timestamp(document, timestamp))
        return result

    def _randomize_entities(self, document: dict[str, Any]) -> None:
        data = document.setdefault("data", {})
        if not isinstance(data, dict):
            data = {}
            document["data"] = data
        old_source = str(data.get("srcip", ""))
        old_destination = str(data.get("dstip", ""))
        source = f"198.51.100.{self._random.randint(1, 254)}"
        destination = (
            f"10.{self._random.randint(0, 20)}.{self._random.randint(0, 254)}."
            f"{self._random.randint(1, 254)}"
        )
        data["srcip"] = source
        data["dstip"] = destination
        data["srcport"] = self._random.randint(1024, 65535)

        agent = document.setdefault("agent", {})
        if not isinstance(agent, dict):
            agent = {}
            document["agent"] = agent
        old_device = str(agent.get("name", "mock-device"))
        base_name = old_device.rsplit("-", 1)[0]
        agent["name"] = f"{base_name}-{self._random.randint(1, 4):02d}"

        raw_log = str(document.get("full_log", ""))
        for old, new in (
            (old_source, source),
            (old_destination, destination),
            (old_device, str(agent["name"])),
        ):
            if old:
                raw_log = raw_log.replace(old, new)
        document["full_log"] = raw_log

    def _scenario_documents(
        self,
        documents: list[dict[str, Any]],
        scenario: str,
        *,
        end: datetime,
        duration_seconds: int,
    ) -> list[dict[str, Any]]:
        fixtures = {str(item.get("fixture_id")): item for item in documents}
        plans: dict[str, tuple[str, int]] = {
            "ssh_bruteforce": ("network-brute-force", 30),
            "port_scan": ("port-scan", 24),
            "syn_flood": ("syn-flood", 30),
            "arp_spoof": ("arp-spoofing", 8),
            "config_change": ("configuration-change", 1),
            "device_silent": ("device-silent", 1),
        }
        fixture_id, event_count = plans[scenario]
        timeline = _timeline(end, event_count, duration_seconds)
        result = [
            self._with_timestamp(fixtures[fixture_id], timestamp) for timestamp in timeline
        ]

        if scenario == "ssh_bruteforce":
            success = copy.deepcopy(fixtures["admin-login-success"])
            success["agent"] = copy.deepcopy(fixtures[fixture_id]["agent"])
            success["decoder"] = {"name": "mikrotik"}
            success["data"] = copy.deepcopy(fixtures[fixture_id]["data"])
            success["rule"] = {
                "id": "100220",
                "level": 7,
                "description": "Administrator login succeeded after repeated failures",
                "groups": ["admin_login_success", "authentication_success"],
            }
            success["full_log"] = (
                "oct/26/2026 12:02:07 system,info account user admin logged in "
                "from 198.51.100.23 via ssh"
            )
            result.append(self._with_timestamp(success, end))
        return result
