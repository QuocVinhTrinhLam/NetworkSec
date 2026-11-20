"""Run the realistic mock alert source through the production ingestion path."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Mapping, Sequence
from typing import cast

from app.adapters.mock import DEFAULT_SEVERITY_DISTRIBUTION, SCENARIOS, MockAdapter, MockMode
from app.config import get_settings
from app.db import Database
from app.services.ingestion import IngestionPipeline


def parse_distribution(value: str) -> Mapping[str, float]:
    """Parse `severity=weight` pairs supplied by CLI or environment."""
    if not value.strip():
        return DEFAULT_SEVERITY_DISTRIBUTION
    try:
        result = {
            severity.strip().lower(): float(weight)
            for item in value.split(",")
            for severity, weight in [item.split("=", 1)]
        }
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "use low=0.1,medium=0.3,high=0.35,critical=0.25"
        ) from error
    if set(result) != {"low", "medium", "high", "critical"}:
        raise argparse.ArgumentTypeError("distribution must define low, medium, high and critical")
    return result


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser without reading application secrets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("replay", "random", "scenario"),
        default=os.getenv("MOCK_GENERATION_MODE", "replay"),
    )
    parser.add_argument("--scenario", choices=SCENARIOS, default=os.getenv("MOCK_SCENARIO"))
    parser.add_argument(
        "--duration",
        type=int,
        default=int(os.getenv("MOCK_DURATION_SECONDS", "60")),
        help="Simulated event-window duration in seconds.",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=float(os.getenv("MOCK_RATE_PER_SECOND", "0")),
        help="Alerts emitted per second; zero emits immediately.",
    )
    parser.add_argument("--count", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None, help="Deterministic random seed.")
    parser.add_argument(
        "--seed-days",
        type=int,
        default=0,
        help="Populate historical random data across this many days (use 7 for the demo seed).",
    )
    parser.add_argument(
        "--severity-distribution",
        type=parse_distribution,
        default=parse_distribution(os.getenv("MOCK_SEVERITY_DISTRIBUTION", "")),
    )
    return parser


async def run(args: argparse.Namespace) -> int:
    """Build the selected adapter and persist all of its output."""
    settings = get_settings()
    database = Database(settings.database_path)
    database.initialize()

    mode = cast(MockMode, "scenario" if args.scenario else args.mode)
    duration = max(1, args.duration)
    count = args.count if args.count is not None else 100
    if args.seed_days:
        if args.seed_days < 1:
            raise ValueError("seed-days must be positive")
        mode = "random"
        duration = args.seed_days * 24 * 60 * 60
        count = args.count if args.count is not None else args.seed_days * 48

    adapter = MockAdapter(
        mode=mode,
        scenario=args.scenario,
        count=max(0, count),
        duration_seconds=duration,
        rate_per_second=max(0, args.rate),
        severity_distribution=args.severity_distribution,
        fixtures_path=settings.mock_fixture_path,
        severity_map_path=settings.severity_config,
        catalog_path=settings.rules_catalog,
        seed=args.seed,
    )
    pipeline = IngestionPipeline(adapter, database)
    inserted = 0
    while not adapter.exhausted:
        inserted += await pipeline.run_once()
    return inserted


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point used by Docker, Make and local demos."""
    args = build_parser().parse_args(argv)
    inserted = asyncio.run(run(args))
    print(f"Stored {inserted} new mock alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
