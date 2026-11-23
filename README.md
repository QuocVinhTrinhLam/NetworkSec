# Network Event Management N4.2

Hệ thống quản lý sự kiện mạng nhẹ cho router, switch và firewall. Dự án thu thập Syslog, chuẩn hóa sự kiện, tổng hợp cảnh báo và hỗ trợ giám sát; đây không phải nền tảng SOC/SIEM đầy đủ.

## Kiến trúc

```text
GNS3 / Loghub / Syslog Generator
                │ TCP/UDP
                ▼
             rsyslog ──► raw.log
                │
          processor.jsonl
                ▼
        Python Processing Worker
      parse → normalize → correlate (SQLite)
          │                 │
          ▼                 ▼
         Loki           PostgreSQL
          │                 │
       Grafana      Dashboard / Telegram
```

- `rsyslog` nhận Syslog TCP/UDP và giữ raw log.
- Worker có checkpoint, khôi phục sau restart và chống xử lý trùng.
- Loki lưu sự kiện chuẩn hóa cho Grafana và tra cứu qua API. PostgreSQL lưu sự cố, lịch sử,
  ACK, tham chiếu bằng chứng và trạng thái gửi Telegram.
- Custom Dashboard FastAPI/Jinja dùng cho hàng đợi, ACK, Resolve và xuất CSV. Telegram chạy
  qua profile tùy chọn `notifications`.
- OSPFv2 hỗ trợ Down, Full và các trạng thái trung gian từ fixture Cisco IOS và MikroTik
  RouterOS v7. Hai góc nhìn dùng cùng một sự cố khi có mapping link. Xem
  [quy tắc tương quan](docs/correlation.md#định-danh-adjacency).
- Không sử dụng Kafka, Redis hoặc Wazuh.

## Khởi động nhanh

Yêu cầu: Python 3.12, Git, Docker Engine và Docker Compose v2. Ubuntu Server là môi trường triển khai đích.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
python -m app.password_hash
```

PowerShell dùng `.venv\Scripts\Activate.ps1` và `Copy-Item .env.example .env`.

Điền tối thiểu trong `.env`:

- `POSTGRES_PASSWORD`
- `SESSION_SECRET` dài ít nhất 32 ký tự ngẫu nhiên
- `ADMIN_PASSWORD_HASH`
- `GRAFANA_ADMIN_PASSWORD` nếu chạy Grafana

Kiểm tra Compose mà không in resolved environment:

```bash
docker compose --file compose.yaml config --quiet
```

Khởi động pipeline chính:

```bash
docker compose up -d --build --wait postgres loki rsyslog processor dashboard
docker compose up -d --wait grafana
docker compose ps
```

Địa chỉ mặc định:

- Dashboard: `http://127.0.0.1:8000`
- Grafana: `http://127.0.0.1:3000`
- Syslog TCP/UDP: `127.0.0.1:5514`

Khi operator triển khai Ubuntu để nhận Syslog từ GNS3, đặt `SYSLOG_BIND_HOST` thành địa chỉ
NIC lab thực tế đã được cấu hình trên Ubuntu. Xem [hướng dẫn triển khai và kiểm thử live](docs/deployment.md#triển-khai-ospf-trên-ubuntu).

## Thử pipeline Syslog

Sinh 100 event có sequence ID:

```bash
docker compose --profile syslog-tools run --rm syslog-generator
```

Replay fixture Loghub:

```bash
docker compose --profile syslog-tools run --rm syslog-generator \
  python -m app.syslog_generator --protocol tcp --rate 50 --count 0 \
  --loghub-file /app/fixtures/logs/cisco-ios.log
```

Theo dõi processor:

```bash
docker compose logs --tail=100 processor
```

TCP được ưu tiên. UDP là best-effort và có thể mất event khi quá tải.

## Telegram

Sau khi điền `TELEGRAM_BOT_TOKEN` và `ALLOWED_CHAT_IDS` trong `.env`:

```bash
docker compose --profile notifications up -d --build bot
```

`APP_URL` nên là URL Dashboard qua mạng mà người nhận có thể truy cập. Bot gửi một thẻ Down
cho mỗi sự cố đủ ngưỡng và cập nhật thẻ sau xác nhận Full. Xem [hành vi gửi và retry](docs/dashboard_notifications.md).

## Kiểm thử

```bash
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m mypy app
python -m pytest -m "not e2e and not syslog_integration and not storage_integration and not processor_integration" --cov=app
```

[Testing runbook](docs/testing.md#kiểm-thử-ospf) có lệnh chạy PostgreSQL/Loki cô lập và
phân biệt kiểm thử phần mềm, kiểm thử TCP/UDP qua Docker, snapshot GNS3 và kiểm thử thiết bị live.

## Tài liệu

- [Kiến trúc](docs/architecture.md) và [triển khai](docs/deployment.md)
- [Processing Worker](docs/processor.md) và [Syslog collection](docs/syslog_collection.md)
- [Parsing](docs/parsing.md) và [correlation](docs/correlation.md)
- [API](docs/api.md) và [storage](docs/storage.md)
- [Kiểm thử](docs/testing.md) và [benchmark](docs/performance.md)
- [GNS3 integration](gns3/docs/phase7-syslog-integration.md) và [demo](docs/demo-phase8.md)

## An toàn

- Không commit `.env`, token, password, private key, log thật hoặc packet capture.
- Giữ dashboard, Loki, PostgreSQL và Grafana trên loopback mặc định.
- Xem Syslog, HTTP input và Telegram data là dữ liệu không tin cậy.
- Không chạy `docker compose down -v`; thao tác này xóa volume và raw spool.
- Không sửa GNS3, deploy, commit hoặc push khi chưa được phê duyệt.
- `compose.yaml` là Compose model duy nhất của dự án.
