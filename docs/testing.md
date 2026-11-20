# Testing runbook

## Fast checks

```bash
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m mypy app
python -m pytest -m "not e2e and not syslog_integration and not storage_integration and not processor_integration"
```

## Phase 8 benchmark tests

```bash
python -m pytest tests/test_benchmark.py
python -m app.benchmark --mode local --rates 100 500 1000 --duration 1 --repetitions 1
```

Unit test xác minh generated Cisco messages là unique/parsable, local TCP không loss,
trace count bằng processed count và chart không được tạo từ row chưa đo.

## Docker integration

Không chạy trên workstation thiếu Docker. Trên Ubuntu:

```bash
docker compose config --quiet
docker compose up -d --wait rsyslog
RUN_SYSLOG_INTEGRATION=1 python -m pytest -m syslog_integration tests/integration
python -m app.benchmark --mode compose --duration 10 --repetitions 3
```

Storage integration cần PostgreSQL/Loki healthy và environment đã bảo vệ:

```bash
RUN_STORAGE_INTEGRATION=1 python -m pytest -m storage_integration
```

Full pipeline integration cần toàn bộ stack healthy. Test gửi 50 event, restart processor (không xóa
volume), gửi 50 event còn lại, xác minh aggregate `count=100`, Loki/raw trace, replay idempotency và
notification claim không lặp. Nạp `POSTGRES_DSN` từ environment bảo vệ, không ghi DSN vào command log:

```bash
docker compose up -d --build --wait postgres loki rsyslog processor dashboard
RUN_PROCESSOR_INTEGRATION=1 python -m pytest -m processor_integration tests/integration
```

Test này chưa được chạy trên workstation nếu Docker không sẵn có; skipped/NOT RUN không được báo PASS.

Không dùng `docker compose down -v`; raw spool và database là evidence/recovery state.

## UI E2E

```bash
python -m playwright install chromium
python -m pytest -m e2e
```

## Evidence checklist

- Ghi Git revision, image digest, OS/kernel, CPU/RAM và UTC start/end.
- Giữ `manifest.json`, CSV và SVG của run; không commit raw log/packet capture.
- Tách live GNS3, replay, synthetic và local preflight.
- Failure/NOT_RUN không được chuyển thành zero hoặc pass.
- Báo warning, skipped test và service restart cùng kết quả.
