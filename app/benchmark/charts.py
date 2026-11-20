"""Dependency-free SVG charts for benchmark CSV results."""

from __future__ import annotations

import csv
import html
from collections import defaultdict
from pathlib import Path
from statistics import fmean
from typing import Any

COLORS = ("#2563eb", "#16a34a", "#dc2626", "#9333ea")


def render_charts(results_path: Path, output_dir: Path) -> tuple[Path, ...]:
    """Render summary SVGs from completed benchmark rows."""
    with results_path.open(newline="", encoding="utf-8") as source:
        rows = [row for row in csv.DictReader(source) if row["status"] == "COMPLETED"]
    if not rows:
        raise ValueError("results CSV has no completed benchmark rows")

    grouped: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["target_rate_eps"])].append(row)
    rates = sorted(grouped)

    def averages(fields: tuple[str, ...]) -> list[list[float]]:
        values_by_field: list[list[float]] = []
        for field in fields:
            values_by_rate = []
            for rate in rates:
                values = [float(row[field]) for row in grouped[rate] if row.get(field)]
                values_by_rate.append(fmean(values) if values else 0.0)
            values_by_field.append(values_by_rate)
        return values_by_field

    compose_resources_present = any(row.get("compose_peak_cpu_percent") for row in rows)
    cpu_names = ("Runner", "Compose services") if compose_resources_present else ("Runner",)
    cpu_fields = (
        ("runner_peak_cpu_percent", "compose_peak_cpu_percent")
        if compose_resources_present
        else ("runner_peak_cpu_percent",)
    )
    memory_names = cpu_names
    memory_fields = (
        ("runner_peak_memory_mib", "compose_peak_memory_mib")
        if compose_resources_present
        else ("runner_peak_memory_mib",)
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    charts = (
        _grouped_bar_chart(
            output_dir / "throughput.svg",
            "Target and observed throughput",
            rates,
            ("Target", "Received", "Processed"),
            averages(("target_rate_eps", "received_rate_eps", "processing_rate_eps")),
            "events/second",
        ),
        _grouped_bar_chart(
            output_dir / "latency.svg",
            "End-to-end latency percentiles",
            rates,
            ("p50", "p95", "p99"),
            averages(("e2e_latency_p50_ms", "e2e_latency_p95_ms", "e2e_latency_p99_ms")),
            "milliseconds",
        ),
        _grouped_bar_chart(
            output_dir / "quality.svg",
            "Loss and parse failure rates",
            rates,
            ("Loss", "Parse failure"),
            averages(("loss_rate_percent", "parse_failure_rate_percent")),
            "percent",
        ),
        _grouped_bar_chart(
            output_dir / "cpu.svg",
            "Peak CPU utilization",
            rates,
            cpu_names,
            averages(cpu_fields),
            "percent of one CPU",
        ),
        _grouped_bar_chart(
            output_dir / "memory.svg",
            "Peak memory utilization",
            rates,
            memory_names,
            averages(memory_fields),
            "MiB",
        ),
        _grouped_bar_chart(
            output_dir / "aggregation.svg",
            "Alert-count reduction",
            rates,
            ("Reduction",),
            averages(("aggregation_reduction_percent",)),
            "percent",
        ),
    )
    return charts


def _grouped_bar_chart(
    path: Path,
    title: str,
    rates: list[int],
    series_names: tuple[str, ...],
    series_values: list[list[float]],
    unit: str,
) -> Path:
    width, height = 920, 520
    left, right, top, bottom = 90, 30, 70, 90
    plot_width = width - left - right
    plot_height = height - top - bottom
    maximum = max((value for values in series_values for value in values), default=0.0)
    maximum = maximum if maximum > 0 else 1.0
    group_width = plot_width / max(1, len(rates))
    bar_width = min(50.0, group_width * 0.75 / max(1, len(series_names)))

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="35" text-anchor="middle" '
        f'font-family="sans-serif" font-size="21" font-weight="bold">{html.escape(title)}</text>',
    ]
    for tick in range(6):
        value = maximum * tick / 5
        y = top + plot_height - plot_height * tick / 5
        parts.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#e5e7eb"/>'
        )
        parts.append(
            f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-family="sans-serif" font-size="12">{value:.2f}</text>'
        )
    parts.append(
        f'<text x="20" y="{top + plot_height / 2}" text-anchor="middle" '
        f'transform="rotate(-90 20 {top + plot_height / 2})" '
        f'font-family="sans-serif" font-size="13">{html.escape(unit)}</text>'
    )

    for rate_index, rate in enumerate(rates):
        center = left + group_width * (rate_index + 0.5)
        total_bars = len(series_names) * bar_width
        for series_index, _name in enumerate(series_names):
            value = series_values[series_index][rate_index]
            bar_height = plot_height * value / maximum
            x = center - total_bars / 2 + series_index * bar_width
            y = top + plot_height - bar_height
            color = COLORS[series_index % len(COLORS)]
            parts.append(
                f'<rect x="{x + 2:.1f}" y="{y:.1f}" width="{bar_width - 4:.1f}" '
                f'height="{bar_height:.1f}" fill="{color}"><title>{value:.4f}</title></rect>'
            )
        parts.append(
            f'<text x="{center:.1f}" y="{top + plot_height + 25}" text-anchor="middle" '
            f'font-family="sans-serif" font-size="13">{rate} logs/s</text>'
        )

    legend_x = left
    for index, name in enumerate(series_names):
        color = COLORS[index % len(COLORS)]
        parts.append(
            f'<rect x="{legend_x}" y="{height - 35}" width="14" height="14" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{legend_x + 20}" y="{height - 23}" font-family="sans-serif" '
            f'font-size="12">{html.escape(name)}</text>'
        )
        legend_x += 150
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def chart_manifest(paths: tuple[Path, ...]) -> list[dict[str, Any]]:
    """Return small chart metadata without embedding SVG content."""
    return [{"name": path.name, "bytes": path.stat().st_size} for path in paths]
