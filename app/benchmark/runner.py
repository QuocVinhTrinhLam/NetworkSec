"""Measured TCP ingress, parsing, and correlation benchmark scenarios."""

from __future__ import annotations

import csv
import ctypes
import json
import math
import platform
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from app.benchmark.charts import render_charts
from app.parsers import parse_syslog
from app.schemas.event import ParseStatus
from app.services.correlation import CorrelationEngine

BenchmarkMode = Literal["local", "compose"]


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    """Validated settings shared by all benchmark scenarios."""

    mode: BenchmarkMode = "local"
    rates: tuple[int, ...] = (100, 500, 1000)
    duration_seconds: float = 10.0
    repetitions: int = 3
    host: str = "127.0.0.1"
    port: int = 5514
    output_root: Path = Path("artifacts/benchmarks")
    run_id: str | None = None
    receive_timeout_seconds: float = 15.0
    sample_interval_seconds: float = 0.25

    def __post_init__(self) -> None:
        if not self.rates or any(rate <= 0 for rate in self.rates):
            raise ValueError("rates must contain positive integers")
        if self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if self.repetitions < 1:
            raise ValueError("repetitions must be at least 1")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.receive_timeout_seconds <= 0 or self.sample_interval_seconds <= 0:
            raise ValueError("timeouts and sampling intervals must be positive")


@dataclass(slots=True)
class ResourceSample:
    run_id: str
    scenario: str
    repetition: int
    sample_index: int
    elapsed_seconds: float
    source: str
    cpu_percent: float
    memory_mib: float


@dataclass(slots=True)
class ScenarioResult:
    run_id: str
    started_at: str
    environment: str
    mode: str
    latency_basis: str
    target_rate_eps: int
    duration_seconds: float
    repetition: int
    generated_events: int = 0
    sent_events: int = 0
    received_events: int = 0
    processed_events: int = 0
    parse_failures: int = 0
    alert_count: int = 0
    largest_alert_count: int = 0
    trace_events: int = 0
    send_elapsed_seconds: float = 0.0
    ingress_elapsed_seconds: float = 0.0
    processing_elapsed_seconds: float = 0.0
    total_elapsed_seconds: float = 0.0
    generated_rate_eps: float = 0.0
    target_achievement_percent: float = 0.0
    received_rate_eps: float = 0.0
    processing_rate_eps: float = 0.0
    loss_rate_percent: float = 0.0
    parse_failure_rate_percent: float = 0.0
    ingress_latency_p50_ms: float = 0.0
    ingress_latency_p95_ms: float = 0.0
    ingress_latency_p99_ms: float = 0.0
    e2e_latency_p50_ms: float = 0.0
    e2e_latency_p95_ms: float = 0.0
    e2e_latency_p99_ms: float = 0.0
    runner_peak_cpu_percent: float = 0.0
    runner_peak_memory_mib: float = 0.0
    compose_peak_cpu_percent: float | None = None
    compose_peak_memory_mib: float | None = None
    events_per_alert: float = 0.0
    aggregation_reduction_percent: float = 0.0
    status: str = "COMPLETED"
    error: str = ""


@dataclass(frozen=True, slots=True)
class ReceivedRecord:
    payload: bytes
    received_at: datetime
    received_monotonic: float


class TcpLineReceiver:
    """Small local receiver used only for non-Docker preflight measurements."""

    def __init__(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(1)
        self._server.settimeout(0.2)
        self.port = int(self._server.getsockname()[1])
        self.records: list[ReceivedRecord] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="benchmark-receiver", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=2)

    def wait_for(self, count: int, timeout: float) -> list[ReceivedRecord]:
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            with self._lock:
                if len(self.records) >= count:
                    return list(self.records)
            time.sleep(0.01)
        with self._lock:
            return list(self.records)

    def _run(self) -> None:
        try:
            connection, _ = self._server.accept()
        except (TimeoutError, OSError):
            return
        connection.settimeout(0.2)
        buffer = b""
        with connection:
            while not self._stop.is_set():
                try:
                    chunk = connection.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    payload, buffer = buffer.split(b"\n", 1)
                    observed = ReceivedRecord(payload, datetime.now(UTC), time.perf_counter())
                    with self._lock:
                        self.records.append(observed)


class ProcessResourceSampler:
    """Sample this benchmark process without third-party dependencies."""

    def __init__(self, run_id: str, scenario: str, repetition: int, interval: float) -> None:
        self.run_id = run_id
        self.scenario = scenario
        self.repetition = repetition
        self.interval = interval
        self.samples: list[ResourceSample] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="process-sampler", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        started = previous_wall = time.perf_counter()
        previous_cpu = time.process_time()
        sample_index = 0
        while not self._stop.wait(self.interval):
            now = time.perf_counter()
            cpu = time.process_time()
            wall_delta = max(now - previous_wall, 1e-9)
            cpu_percent = (cpu - previous_cpu) / wall_delta * 100.0
            self.samples.append(
                ResourceSample(
                    self.run_id,
                    self.scenario,
                    self.repetition,
                    sample_index,
                    now - started,
                    "benchmark-runner",
                    cpu_percent,
                    _rss_bytes() / (1024 * 1024),
                )
            )
            previous_wall, previous_cpu = now, cpu
            sample_index += 1


class ComposeStatsSampler:
    """Collect read-only container metrics with docker stats --no-stream."""

    def __init__(self, run_id: str, scenario: str, repetition: int, interval: float) -> None:
        self.run_id = run_id
        self.scenario = scenario
        self.repetition = repetition
        self.interval = interval
        self.samples: list[ResourceSample] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="compose-sampler", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(2.0, self.interval * 2))

    def _run(self) -> None:
        started = time.perf_counter()
        sample_index = 0
        while not self._stop.is_set():
            ids = _command(["docker", "compose", "ps", "-q"], check=False).stdout.split()
            if ids:
                result = _command(
                    [
                        "docker",
                        "stats",
                        "--no-stream",
                        "--format",
                        "{{json .}}",
                        *ids,
                    ],
                    check=False,
                )
                for line in result.stdout.splitlines():
                    try:
                        item = json.loads(line)
                        self.samples.append(
                            ResourceSample(
                                self.run_id,
                                self.scenario,
                                self.repetition,
                                sample_index,
                                time.perf_counter() - started,
                                str(item.get("Name", "container")),
                                _percent(str(item.get("CPUPerc", "0%"))),
                                _memory_mib(str(item.get("MemUsage", "0B / 0B"))),
                            )
                        )
                    except (json.JSONDecodeError, ValueError):
                        continue
            sample_index += 1
            self._stop.wait(self.interval)


def run_benchmarks(config: BenchmarkConfig) -> Path:
    """Run every configured scenario and write CSV plus SVG artifacts."""
    run_id = config.run_id or datetime.now(UTC).strftime("run-%Y%m%dT%H%M%SZ")
    output_dir = config.output_root / run_id
    output_dir.mkdir(parents=True, exist_ok=False)
    results: list[ScenarioResult] = []
    resources: list[ResourceSample] = []

    for repetition in range(1, config.repetitions + 1):
        for rate in config.rates:
            try:
                result, samples = _run_scenario(config, run_id, rate, repetition, output_dir)
            except Exception as exc:
                result = ScenarioResult(
                    run_id=run_id,
                    started_at=datetime.now(UTC).isoformat(),
                    environment=_environment_label(),
                    mode=config.mode,
                    latency_basis="unavailable",
                    target_rate_eps=rate,
                    duration_seconds=config.duration_seconds,
                    repetition=repetition,
                    status="FAILED",
                    error=type(exc).__name__,
                )
                samples = []
            results.append(result)
            resources.extend(samples)
            _write_csv(output_dir / "results.csv", results)
            _write_csv(output_dir / "resource_samples.csv", resources)

    if any(result.status == "COMPLETED" for result in results):
        render_charts(output_dir / "results.csv", output_dir / "charts")
    _write_manifest(output_dir, config, results)
    return output_dir


def _run_scenario(
    config: BenchmarkConfig,
    run_id: str,
    rate: int,
    repetition: int,
    output_dir: Path,
) -> tuple[ScenarioResult, list[ResourceSample]]:
    scenario = f"{rate}eps-r{repetition}"
    messages = _build_cisco_messages(rate, config.duration_seconds)
    scenario_started = time.perf_counter()
    process_sampler = ProcessResourceSampler(
        run_id, scenario, repetition, config.sample_interval_seconds
    )
    compose_sampler = (
        ComposeStatsSampler(run_id, scenario, repetition, config.sample_interval_seconds)
        if config.mode == "compose"
        else None
    )
    process_sampler.start()
    if compose_sampler is not None:
        compose_sampler.start()

    try:
        if config.mode == "local":
            records, send_times, send_elapsed, ingress_elapsed = _local_ingress(
                messages, rate, config.receive_timeout_seconds
            )
            latency_basis = "per_event_socket_to_batch_processor"
        else:
            records, send_times, send_elapsed, ingress_elapsed = _compose_ingress(
                messages, config, rate
            )
            latency_basis = "raw_spool_batch_upper_bound"

        processing_started = time.perf_counter()
        database_path = output_dir / f"correlation-{scenario}.db"
        engine = CorrelationEngine.from_files(database_path, Path("config/correlation_rules.yaml"))
        parse_failures = 0
        processed = 0
        ingress_latencies: list[float] = []
        e2e_latencies: list[float] = []
        for record in records:
            sent_at = send_times.get(record.payload)
            if sent_at is not None:
                ingress_latencies.append((record.received_monotonic - sent_at) * 1000)
            parsed = parse_syslog(
                record.payload.decode("utf-8", errors="strict"),
                received_at=record.received_at,
                source_host="benchmark-switch",
            )
            if parsed.status is not ParseStatus.PARSED or parsed.event is None:
                parse_failures += 1
                continue
            engine.process(parsed.event)
            processed += 1
            if sent_at is not None:
                e2e_latencies.append((time.perf_counter() - sent_at) * 1000)
        processing_elapsed = time.perf_counter() - processing_started
        alerts = engine.store.list_alerts()
        with engine.store.connect() as connection:
            trace_events = int(
                connection.execute("SELECT COUNT(*) FROM correlation_events").fetchone()[0]
            )
        total_elapsed = time.perf_counter() - scenario_started
    finally:
        process_sampler.stop()
        if compose_sampler is not None:
            compose_sampler.stop()

    resource_samples = process_sampler.samples + (
        compose_sampler.samples if compose_sampler is not None else []
    )
    runner_cpu = max((item.cpu_percent for item in process_sampler.samples), default=0.0)
    runner_memory = max((item.memory_mib for item in process_sampler.samples), default=0.0)
    compose_cpu, compose_memory = (
        _peak_compose_totals(compose_sampler.samples)
        if compose_sampler is not None
        else (None, None)
    )
    generated = len(messages)
    received = len(records)
    alert_count = len(alerts)
    largest_alert = max((alert.count for alert in alerts), default=0)
    return (
        ScenarioResult(
            run_id=run_id,
            started_at=datetime.now(UTC).isoformat(),
            environment=_environment_label(),
            mode=config.mode,
            latency_basis=latency_basis,
            target_rate_eps=rate,
            duration_seconds=config.duration_seconds,
            repetition=repetition,
            generated_events=generated,
            sent_events=len(send_times),
            received_events=received,
            processed_events=processed,
            parse_failures=parse_failures,
            alert_count=alert_count,
            largest_alert_count=largest_alert,
            trace_events=trace_events,
            send_elapsed_seconds=send_elapsed,
            ingress_elapsed_seconds=ingress_elapsed,
            processing_elapsed_seconds=processing_elapsed,
            total_elapsed_seconds=total_elapsed,
            generated_rate_eps=len(send_times) / max(send_elapsed, 1e-9),
            target_achievement_percent=(len(send_times) / max(send_elapsed, 1e-9) / rate * 100),
            received_rate_eps=received / max(ingress_elapsed, 1e-9),
            processing_rate_eps=processed / max(processing_elapsed, 1e-9),
            loss_rate_percent=(len(send_times) - received) / max(1, len(send_times)) * 100,
            parse_failure_rate_percent=parse_failures / max(1, received) * 100,
            ingress_latency_p50_ms=_percentile(ingress_latencies, 50),
            ingress_latency_p95_ms=_percentile(ingress_latencies, 95),
            ingress_latency_p99_ms=_percentile(ingress_latencies, 99),
            e2e_latency_p50_ms=_percentile(e2e_latencies, 50),
            e2e_latency_p95_ms=_percentile(e2e_latencies, 95),
            e2e_latency_p99_ms=_percentile(e2e_latencies, 99),
            runner_peak_cpu_percent=runner_cpu,
            runner_peak_memory_mib=runner_memory,
            compose_peak_cpu_percent=compose_cpu,
            compose_peak_memory_mib=compose_memory,
            events_per_alert=processed / max(1, alert_count),
            aggregation_reduction_percent=(1 - alert_count / max(1, processed)) * 100,
        ),
        resource_samples,
    )


def _build_cisco_messages(rate: int, duration_seconds: float) -> list[bytes]:
    count = max(1, int(round(rate * duration_seconds)))
    base = datetime.now(UTC).replace(second=0, microsecond=0)
    messages = []
    for sequence in range(count):
        event_time = base + timedelta(microseconds=sequence)
        state = "down" if sequence % 2 == 0 else "up"
        timestamp = event_time.strftime("%b %d %H:%M:%S.%f")
        messages.append(
            (
                f"{timestamp}: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, "
                f"changed state to {state}"
            ).encode()
        )
    return messages


def _local_ingress(
    messages: list[bytes], rate: int, timeout: float
) -> tuple[list[ReceivedRecord], dict[bytes, float], float, float]:
    receiver = TcpLineReceiver()
    receiver.start()
    started = time.perf_counter()
    try:
        send_times, elapsed = _send_tcp(messages, "127.0.0.1", receiver.port, rate)
        records = receiver.wait_for(len(messages), timeout)
    finally:
        receiver.stop()
    return records, send_times, elapsed, time.perf_counter() - started


def _compose_ingress(
    messages: list[bytes], config: BenchmarkConfig, rate: int
) -> tuple[list[ReceivedRecord], dict[bytes, float], float, float]:
    _require_compose_rsyslog()
    offset = _spool_size()
    started = time.perf_counter()
    send_times, elapsed = _send_tcp(messages, config.host, config.port, rate)
    expected_bytes = sum(len(message) + 1 for message in messages)
    deadline = time.perf_counter() + config.receive_timeout_seconds
    while time.perf_counter() < deadline and _spool_size() < offset + expected_bytes:
        time.sleep(0.05)
    observed_at = datetime.now(UTC)
    observed_monotonic = time.perf_counter()
    segment = _spool_segment(offset)
    expected = Counter(messages)
    records: list[ReceivedRecord] = []
    for line in segment.splitlines():
        if expected[line] <= 0:
            continue
        expected[line] -= 1
        records.append(ReceivedRecord(line, observed_at, observed_monotonic))
    return records, send_times, elapsed, time.perf_counter() - started


def _send_tcp(
    messages: list[bytes], host: str, port: int, rate: int
) -> tuple[dict[bytes, float], float]:
    send_times: dict[bytes, float] = {}
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=5.0) as connection:
        for index, message in enumerate(messages):
            deadline = started + index / rate
            delay = deadline - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            send_times[message] = time.perf_counter()
            connection.sendall(message + b"\n")
    return send_times, time.perf_counter() - started


def _require_compose_rsyslog() -> None:
    result = _command(["docker", "compose", "ps", "-q", "rsyslog"], check=False)
    if not result.stdout.strip():
        raise RuntimeError("Compose rsyslog service is not running")


def _spool_size() -> int:
    result = _command(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "rsyslog",
            "sh",
            "-c",
            "test -f /var/log/networksec/raw.log && wc -c < /var/log/networksec/raw.log || echo 0",
        ]
    )
    return int(result.stdout.strip())


def _spool_segment(offset: int) -> bytes:
    command = f"tail -c +{offset + 1} /var/log/networksec/raw.log 2>/dev/null || true"
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "rsyslog", "sh", "-c", command],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return result.stdout


def _command(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _write_csv(path: Path, rows: list[Any]) -> None:
    if not rows:
        return
    documents = [asdict(row) for row in rows]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(documents[0]))
        writer.writeheader()
        writer.writerows(documents)


def _write_manifest(
    output_dir: Path, config: BenchmarkConfig, results: list[ScenarioResult]
) -> None:
    manifest = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "config": {
            **asdict(config),
            "output_root": str(config.output_root),
        },
        "completed": sum(result.status == "COMPLETED" for result in results),
        "failed": sum(result.status == "FAILED" for result in results),
        "python": sys.version,
        "platform": platform.platform(),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def _peak_compose_totals(samples: list[ResourceSample]) -> tuple[float, float]:
    grouped: dict[int, list[ResourceSample]] = {}
    for sample in samples:
        grouped.setdefault(sample.sample_index, []).append(sample)
    return (
        max((sum(item.cpu_percent for item in group) for group in grouped.values()), default=0.0),
        max((sum(item.memory_mib for item in group) for group in grouped.values()), default=0.0),
    )


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile / 100
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def _percent(value: str) -> float:
    return float(value.strip().removesuffix("%") or 0)


def _memory_mib(value: str) -> float:
    usage = value.split("/", 1)[0].strip()
    units = {"GiB": 1024, "MiB": 1, "KiB": 1 / 1024, "B": 1 / (1024 * 1024)}
    for unit, multiplier in units.items():
        if usage.endswith(unit):
            return float(usage.removesuffix(unit).strip()) * multiplier
    raise ValueError(f"unsupported Docker memory unit: {usage}")


def _rss_bytes() -> int:
    if sys.platform == "win32":
        return _windows_rss_bytes()
    status = Path("/proc/self/status")
    if status.exists():
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return 0


def _windows_rss_bytes() -> int:
    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetProcessMemoryInfo.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCounters),
        ctypes.c_ulong,
    )
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int
    handle = kernel32.GetCurrentProcess()
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return 0
    return int(counters.WorkingSetSize)


def _environment_label() -> str:
    return f"{platform.system()}-{platform.machine()}-python{platform.python_version()}"
