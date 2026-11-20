"""CLI for Phase 8 performance benchmark scenarios."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.benchmark.runner import BenchmarkConfig, run_benchmarks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("local", "compose"), default="local")
    parser.add_argument("--rates", type=int, nargs="+", default=(100, 500, 1000))
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/benchmarks"))
    parser.add_argument("--run-id")
    parser.add_argument("--receive-timeout", type=float, default=15.0)
    parser.add_argument("--sample-interval", type=float, default=0.25)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output_dir = run_benchmarks(
        BenchmarkConfig(
            mode=args.mode,
            rates=tuple(args.rates),
            duration_seconds=args.duration,
            repetitions=args.repetitions,
            host=args.host,
            port=args.port,
            output_root=args.output_root,
            run_id=args.run_id,
            receive_timeout_seconds=args.receive_timeout,
            sample_interval_seconds=args.sample_interval,
        )
    )
    print(output_dir)
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    return 1 if manifest["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
