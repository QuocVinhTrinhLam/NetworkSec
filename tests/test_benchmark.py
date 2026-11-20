from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from app.benchmark.charts import render_charts
from app.benchmark.runner import BenchmarkConfig, _build_cisco_messages, run_benchmarks
from app.parsers import parse_syslog
from app.schemas.event import ParseStatus


def test_benchmark_messages_are_unique_supported_link_events() -> None:
    messages = _build_cisco_messages(100, 0.1)

    assert len(messages) == 10
    assert len(set(messages)) == 10
    assert all(
        parse_syslog(
            message.decode(),
            received_at=datetime.now(UTC),
            source_host="benchmark-switch",
        ).status
        is ParseStatus.PARSED
        for message in messages
    )


def test_local_benchmark_exports_measured_csv_and_charts(tmp_path: Path) -> None:
    output = run_benchmarks(
        BenchmarkConfig(
            mode="local",
            rates=(10,),
            duration_seconds=0.2,
            repetitions=1,
            output_root=tmp_path,
            run_id="unit-run",
            receive_timeout_seconds=2,
            sample_interval_seconds=0.01,
        )
    )

    with (output / "results.csv").open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))

    assert len(rows) == 1
    assert rows[0]["status"] == "COMPLETED"
    assert rows[0]["generated_events"] == "2"
    assert rows[0]["received_events"] == "2"
    assert rows[0]["processed_events"] == "2"
    assert rows[0]["parse_failures"] == "0"
    assert rows[0]["alert_count"] == "1"
    assert rows[0]["largest_alert_count"] == "2"
    assert rows[0]["trace_events"] == "2"
    assert manifest["completed"] == 1
    assert manifest["failed"] == 0
    assert len(list((output / "charts").glob("*.svg"))) == 6


def test_chart_renderer_rejects_unmeasured_rows(tmp_path: Path) -> None:
    results = tmp_path / "results.csv"
    results.write_text("status,target_rate_eps\nNOT_RUN,100\n", encoding="utf-8")

    try:
        render_charts(results, tmp_path / "charts")
    except ValueError as exc:
        assert "no completed" in str(exc)
    else:
        raise AssertionError("unmeasured data must not produce charts")
