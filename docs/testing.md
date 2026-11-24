# Testing runbook

## Fast checks

```bash
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m mypy app
python -m pytest -m "not e2e and not syslog_integration and not storage_integration and not processor_integration"
```

## Kiểm thử OSPF

Fast checks dùng fixture mô phỏng và bao phủ parser hai vendor, tương thích schema,
correlation, retry/checkpoint, API, Grafana provisioning và Telegram fake. Kiểm
thử storage dưới đây chạy với PostgreSQL và Loki cô lập đã sẵn sàng. Nạp
`NETWORKSEC_TEST_POSTGRES_DSN` và `NETWORKSEC_TEST_LOKI_URL` từ môi trường thử nghiệm.
Tài khoản PostgreSQL phải tạo được schema riêng cho mỗi test.

```bash
python -m pytest tests/integration/test_postgres_ospf_lifecycle.py tests/integration/test_ospf_loki_queries.py
```

- `test_postgres_ospf_lifecycle.py` kiểm tra migration tăng dần, transaction, replay,
  stale Full, ACK, resolve, API, Grafana views và delivery claims với Telegram fake.
- `test_ospf_spool_to_loki_incident_api_grafana_views_and_telegram` dùng cả hai backend. Test
  chạy với hai CHR và với một cặp MikroTik–Cisco để kiểm tra tương thích. Mỗi ca đưa
  envelope Syslog mô phỏng vào reader thực, restart worker bằng state cũ, kiểm tra hai
  Down cùng incident, Full đến muộn, chứng cứ Loki, bearer/ACK và một lần cập nhật
  thẻ Telegram giả lập sau recovery. Syslog từ thiết bị thật được nghiệm thu riêng.
- `test_ospf_loki_queries.py` chạy sáu biểu thức của dashboard OSPF trên Loki với dữ
  liệu phiên bản `1.0` và `1.1`. Grafana runtime vẫn cần smoke test khi deploy.
- `test_gns3_phase7.py` là test snapshot cũ tám node, bảy link. Checklist nghiệm thu
  R1–R2 trên topology mới nằm trong [hướng dẫn Ubuntu](deployment.md#điều-kiện-lab-và-checklist-nghiệm-thu-live).

Kiểm thử socket TCP/UDP và container restart dùng các opt-in bên dưới. Chạy trên
stack test riêng vì các test đó ghi event và restart processor.

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
docker compose up -d --build --wait
RUN_PROCESSOR_INTEGRATION=1 python -m pytest -m processor_integration tests/integration
```

Test này chưa được chạy trên workstation nếu Docker không sẵn có; skipped/NOT RUN không được báo PASS.

Không dùng `docker compose down -v`; raw spool và database là evidence/recovery state.

## Grafana browser smoke test

Trên stack test, đăng nhập Grafana và kiểm tra health của hai datasource. Mở **Incident
Operations**, chọn một incident fixture và xác nhận lịch sử chỉ hiển thị incident đó. Đối
chiếu trạng thái operator và thời điểm Full đã xác nhận với `/api/v1/alerts/{id}/evidence`.
Mở **OSPF Observability** và kiểm tra hai router xuất hiện trong log stream. Kiểm tra
`/dashboard`, `/login` và `/docs` trên cổng API trả `404`. [Cấu hình datasource](grafana-integration.md).

## Evidence checklist

- Ghi Git revision, image digest, OS/kernel, CPU/RAM và UTC start/end.
- Giữ `manifest.json`, CSV và SVG của run; không commit raw log/packet capture.
- Tách live GNS3, replay, synthetic và local preflight.
- Failure/NOT_RUN không được chuyển thành zero hoặc pass.
- Báo warning, skipped test và service restart cùng kết quả.
