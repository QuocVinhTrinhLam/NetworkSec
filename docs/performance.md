# Phase 8 — Performance Benchmarking

## Phạm vi và tính trung thực của số liệu

Benchmark tách hai boundary hiện có:

1. TCP generation/ingress: gửi Cisco Link Up/Down hợp lệ, đếm message thực nhận.
2. Batch processing: parse `NormalizedEvent 1.0`, correlate và ghi trace/aggregate SQLite.

Repository chưa có continuous worker đọc raw spool rồi ghi Loki/PostgreSQL. Vì vậy kết quả
không được gọi là full end-to-end production. Compose mode đo rsyslog/raw spool thật và
`docker stats`; local mode chỉ là preflight trên loopback. CSV ghi `mode` và
`latency_basis` để hai loại này không bị trộn.

Không có số đo Ubuntu nào được suy diễn từ Windows. File
[`benchmarks/ubuntu-results.csv`](benchmarks/ubuntu-results.csv) chỉ có schema vì target
Ubuntu chưa được truy cập và máy audit không có Docker CLI.

## Công cụ tái lập

```bash
python -m app.benchmark \
  --mode local \
  --rates 100 500 1000 \
  --duration 10 \
  --repetitions 3
```

Compose/Ubuntu, sau khi rsyslog healthy:

```bash
docker compose up -d --wait rsyslog
python -m app.benchmark \
  --mode compose \
  --host 127.0.0.1 \
  --port 5514 \
  --rates 100 500 1000 \
  --duration 10 \
  --repetitions 3
```

Mỗi run tạo thư mục mới trong `artifacts/benchmarks/` gồm:

- `results.csv`: summary theo rate/repetition.
- `resource_samples.csv`: CPU/RSS của runner và, ở Compose mode, từng container.
- `manifest.json`: tham số, Python/platform và completed/failed count.
- `charts/*.svg`: throughput, latency, loss/parse failure, CPU, RAM và aggregation.
- SQLite correlation riêng cho từng scenario để trace count có thể audit.

Artifact được Git-ignore và không chứa raw payload. Runner không start/stop GNS3, không
xóa volume và không mount Docker socket vào container. Compose mode chỉ đọc raw spool qua
`docker compose exec` và lấy resource bằng `docker stats --no-stream`.

## Phương pháp

- Transport: TCP newline framing, cùng interface `GigabitEthernet0/2`.
- Event: timestamp microsecond khác nhau, luân phiên Link Down/Up, cùng fixed 60-second
  correlation window.
- Số event: `target_rate × duration`.
- Pacing: absolute monotonic deadline; nếu scheduler trễ, sender bắt kịp thay vì cộng dồn
  oversleep.
- Received: local receiver đếm payload chính xác; Compose đếm đúng payload trong phần raw
  spool bắt đầu từ byte offset trước scenario.
- Processed: chỉ event parse thành công; unknown/malformed tính parse failure.
- Loss: `(sent - received) / sent`.
- Latency local: send → socket receive và send → hoàn tất parse/correlation.
- Latency Compose: send → batch raw-spool observation; đây là upper bound, không phải
  timestamp ingest per-event.
- CPU: percent theo một logical CPU; có thể vượt 100% khi nhiều thread chạy đồng thời.
- RAM: process working set/RSS; Compose mode cộng memory usage của container theo sample.
- Aggregation: `processed / alert_count`, reduction là `1 - alert_count / processed`.

Default chính thức là 10 giây, ba repetition; chạy warm-up riêng trước khi lấy số liệu.
Đồng bộ NTP/clock, giữ cùng image/config, không chạy antivirus scan/build hoặc workload
khác trong measurement window. Không xóa raw spool giữa run; byte offset cô lập scenario.

## Kết quả thực tế hiện có — Windows local preflight

Môi trường: Windows 11, Intel Core i3-10105F 4 core/8 logical CPU, RAM 15,93 GiB,
Python 3.12.10. Thời lượng chỉ 1 giây và một repetition nên đây là sanity/preflight,
không phải capacity result cho Ubuntu 2 vCPU/5,3 GiB.

Run: `artifacts/benchmarks/phase8-local-preflight-v3-20261119/`.

| Target | Generated/received/processed | Received eps | Processing eps | Loss | Parse fail | E2E p95 | Peak CPU | Peak RSS | Alerts/count |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100/s | 100/100/100 | 100,87 | 92,45 | 0% | 0% | 1.110,51 ms | 125,35% | 34,16 MiB | 1/100 |
| 500/s | 500/500/500 | 495,73 | 105,17 | 0% | 0% | 4.641,99 ms | 114,05% | 38,76 MiB | 1/500 |
| 1.000/s | 1.000/1.000/1.000 | 990,22 | 100,68 | 0% | 0% | 9.639,85 ms | 125,37% | 40,56 MiB | 1/1.000 |

Ingress p50 lần lượt khoảng 0,236 / 0,145 / 0,101 ms trên loopback. Các giá trị này
không đại diện cho GNS3 → Ubuntu hoặc rsyslog. Compose CPU/RAM để trống trong CSV local;
không coi giá trị thiếu là 0.

Aggregation giữ đầy đủ 100/500/1.000 trace và tạo đúng một alert mỗi scenario, tương ứng
reduction 99,0% / 99,8% / 99,9%.

## Bottleneck quan sát được

- Sender/loopback đạt target, nhưng batch processor chỉ khoảng 92–105 events/s.
- `CorrelationStore.persist()` mở connection và commit SQLite cho từng event. Ở 500 và
  1.000/s, backlog làm latency tăng tuyến tính sau khi send kết thúc.
- Processing chỉ bắt đầu sau khi batch nhận đủ; p95 phản ánh batch architecture này.
- Test 1 giây chưa đo steady-state, WAL growth, disk saturation, queue recovery, Loki,
  PostgreSQL hoặc Grafana contention.
- Không có bằng chứng Kafka/Redis cần thiết: bottleneck hiện tại nằm ở per-event SQLite
  transaction và thiếu streaming worker. Tối ưu batch transaction/checkpoint nên được đo
  trước khi thêm broker.

## Tiêu chí acceptance cho Ubuntu

Các tiêu chí dưới đây là mục tiêu, chưa phải kết quả:

- Target achievement từ 95% trở lên ở cả ba rate trong ba repetition.
- TCP raw loss bằng 0 và parse failure bằng 0 với fixture benchmark.
- `trace_events == processed_events` và một alert có `count == processed_events`.
- Processing throughput không thấp hơn ingress throughput trong steady-state; nếu thấp
  hơn phải báo backlog/drain time.
- Không OOM, container restart hoặc rsyslog queue suspension.
- Ghi peak/mean CPU, RAM từng service và dung lượng raw spool trước/sau.

Ubuntu target phải chạy đủ 10 giây × ba repetition và ghi kết quả CSV/chart mới trước khi
đưa ra kết luận capacity hoặc demo con số hiệu năng.

## Tài liệu phép đo

- [Docker runtime metrics](https://docs.docker.com/engine/containers/runmetrics/)
- [docker stats CLI fields](https://docs.docker.com/reference/cli/docker/container/stats/)
