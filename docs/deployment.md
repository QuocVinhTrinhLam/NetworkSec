# Triển khai và vận hành

## Phạm vi hiện tại

Tài liệu này chỉ hướng dẫn môi trường phát triển và Syslog lab. **Chưa triển khai lên Ubuntu Server**. Không có migration production, không mở firewall, không cấu hình TLS và không tạo credential bên ngoài máy phát triển.

## Chạy local bằng Python

1. Cài Python 3.12 và tạo virtual environment.
2. Cài `requirements-dev.txt`.
3. Sao chép `.env.example` thành `.env`.
4. Chạy `python -m app.password_hash`, lưu output vào `ADMIN_PASSWORD_HASH` trong `.env`.
5. Tạo `SESSION_SECRET` ngẫu nhiên tối thiểu 32 byte; không dùng lại giữa các môi trường.
6. Chạy `python -m uvicorn app.main:app --reload --host 127.0.0.1`.
7. Kiểm tra `http://127.0.0.1:8000/health` trước khi đăng nhập.

Không truyền password trực tiếp trên command line hoặc lưu nó trong shell history. Công cụ tạo hash dùng prompt ẩn.

## Chạy local bằng Docker Compose

Docker Engine và Docker Compose v2 phải có sẵn. `compose.yaml` build `docker/Dockerfile` production
không reload/source bind mount. Application container chạy UID/GID 10001, root filesystem chỉ đọc,
drop toàn bộ Linux capabilities và lưu state trong named volume.

```bash
docker compose --file compose.yaml config --quiet
docker compose --file compose.yaml up -d --build --wait postgres loki rsyslog processor dashboard
docker compose --file compose.yaml ps
docker compose --file compose.yaml logs --tail=200 dashboard
```

`config --quiet` được dùng để validation mà không in resolved environment có thể chứa secret. Không dùng
`docker compose config` không kèm `--quiet` trong log CI hoặc khi chia sẻ màn hình. Trước lần chạy đầu
phải điền `POSTGRES_PASSWORD`, `SESSION_SECRET` và `ADMIN_PASSWORD_HASH` trong `.env`; Compose không chứa
giá trị thật.

Bot Telegram chỉ chạy khi có token thật và allowlist chat trong `.env`:

```bash
docker compose --profile notifications up --build dashboard bot
```

Để dừng container mà giữ dữ liệu:

```bash
docker compose down
```

Không dùng `down -v`, `docker system prune` hoặc xóa `monitor-data` nếu chưa sao lưu và chưa được phê duyệt; các lệnh đó có thể xóa SQLite hiện tại.

## Chạy Syslog collector cục bộ

```bash
docker compose up -d --wait rsyslog
docker compose ps rsyslog
docker compose logs --tail=100 rsyslog
```

Mặc định TCP và UDP chỉ publish tại `127.0.0.1:5514`. Để nhận từ GNS3 trên Ubuntu VM, đặt `SYSLOG_BIND_HOST` thành IP interface lab cụ thể; không dùng `0.0.0.0` nếu không có firewall. Raw log và queue lần lượt nằm trong `syslog-raw` và `syslog-queue`. Dừng bằng `docker compose stop rsyslog` hoặc `docker compose down`; không thêm `-v`.

## Processing worker và recovery

Worker dùng ba named volume liên quan: `syslog-raw` được mount read-only; `processor-state` giữ byte
checkpoint, DLQ và correlation trace; Loki/PostgreSQL giữ output nghiệp vụ. Health check thất bại nếu
worker bị storage error hoặc heartbeat quá 30 giây. Xem trạng thái mà không in environment:

```bash
docker compose ps
docker compose logs --tail=100 processor
docker compose exec -T processor python -m app.processor.healthcheck
```

Không sửa checkpoint bằng tay. Khi Loki/PostgreSQL tạm lỗi, khôi phục service và để processor retry
record chưa checkpoint. Khi container processor restart, named volume giữ offset. Nếu spool bị truncate
hoặc thay inode, reader bắt đầu lại từ byte 0 và idempotency key ngăn double-count; phải điều tra nguyên
nhân trước khi tiếp tục. Chưa cấu hình log rotation tự động cho spool, vì rotation phải phối hợp với
checkpoint; theo dõi disk và backup cả `syslog-raw` lẫn `processor-state`.

## Checklist Ubuntu cho Phase 8

Các bước dưới đây là tiêu chí chuẩn bị, chưa được thực hiện:

- Chốt Ubuntu LTS, Docker Engine/Compose versions và digest image.
- Dành CPU/RAM budgets; đo peak trước khi bật Loki/Grafana/PostgreSQL cùng lúc.
- Tạo service accounts, data directories và backup/restore test.
- Đưa secrets qua file permission 0600 hoặc secret manager; không đặt trong Git/Compose YAML.
- Bind management UI vào private interface, thêm TLS reverse proxy và firewall allowlist.
- Bật log rotation, raw-spool retention, disk alerts và clock synchronization.
- Test restart, disk-full, malformed input, duplicate replay, Telegram outage và restore.
- Chỉ deploy sau khi CI xanh và có approval riêng.

## Correlation state Phase 4

Correlation dùng cùng kiểu file SQLite bền vững của ứng dụng; không cần service mới trong Compose. `CorrelationEngine.from_files()` phải nhận đường dẫn nằm trên volume `monitor-data` và `config/correlation_rules.yaml` read-only. Không đặt rule hoặc database vào image layer chứa dữ liệu production.

Khi backup, cần snapshot nhất quán file database cùng WAL/SHM hoặc dừng writer ngắn trước khi copy. Không xóa database để xử lý lỗi schema. Sau restore, có thể replay raw spool: unique `event_id` ngăn count tăng lại, còn aggregate/cooldown đã commit tiếp tục qua restart.

Trước khi đổi rule đang chạy, lưu bản rule cũ cùng backup. Thay `rule_id`, `group_by` hoặc `window_seconds` làm thay đổi aggregate identity; replay với rule mới có thể tạo nhóm mới và phải được xem là migration có chủ đích.

## Storage Phase 5

Tạo `.env` cục bộ và điền `POSTGRES_PASSWORD` ngẫu nhiên, không commit hoặc đưa password lên command line. Xác minh rồi khởi động:

```bash
docker compose config --quiet
docker compose up --build postgres loki dashboard
docker compose ps
```

`postgres-data` và `loki-data` là named volumes. Không dùng `down -v`. PostgreSQL và Loki bind `127.0.0.1` để test/điều tra local; trên Ubuntu không đổi thành `0.0.0.0`. Loki không có auth tích hợp, còn PostgreSQL chỉ nên nhận kết nối từ Compose network/loopback.

FastAPI chạy migration PostgreSQL khi lifespan bắt đầu. Nếu migration lỗi, đọc log dashboard, sửa migration mới hoặc restore backup; không sửa checksum migration đã áp dụng và không xóa volume.

Chạy integration test storage khi stack healthy. Nạp `POSTGRES_DSN` và `LOKI_URL` từ môi trường bảo vệ trước, không đặt secret trong lệnh hoặc shell history:

```bash
RUN_STORAGE_INTEGRATION=1 python -m pytest -m storage_integration
```

Không lưu command có password vào shell history trên máy dùng chung; ưu tiên export từ file permission 0600 hoặc secret manager khi deploy thật.

## Dashboard và notification Phase 6

Đặt `GRAFANA_ADMIN_PASSWORD`, `TELEGRAM_BOT_TOKEN` và `ALLOWED_CHAT_IDS` trong `.env` được bảo vệ. Không dùng password Grafana mặc định. Khởi động Grafana cùng storage:

```bash
docker compose up --build postgres loki grafana dashboard
docker compose --profile notifications up --build bot
```

Grafana datasource/dashboard là read-only provisioning tại `infra/grafana/`; thay đổi file rồi restart/recreate container nhưng giữ `grafana-data`. Custom Dashboard dùng `DASHBOARD_BACKEND=operational` trong Compose. Để chẩn đoán local không có storage, đặt `legacy` rõ ràng; không dùng legacy làm fallback production im lặng.

Grafana, PostgreSQL, Loki và Dashboard đều bind loopback mặc định. Nếu truy cập từ máy Windows host tới Ubuntu VM, dùng SSH tunnel hoặc reverse proxy TLS đã review; không đổi bind thành public chỉ để tiện demo.

Bot PostgreSQL chạy migration `002` trước loop. Không chạy nhiều bot token/worker ngoài Compose trừ khi kiểm tra `FOR UPDATE SKIP LOCKED` và message state dùng chung. Backup PostgreSQL trước migration; không xóa volume để reset delivery state.

## GNS3 Syslog Phase 7

Ubuntu dùng NIC lab riêng `10.10.99.10/24` không có default gateway; default route vẫn ở
NIC quản trị/chính. Đặt `SYSLOG_BIND_HOST=10.10.99.10` và chỉ allow TCP/UDP 5514 từ
`10.10.99.0/24` trên đúng interface. Không dùng `0.0.0.0`, NAT port-forward hoặc public
firewall rule cho Syslog plaintext.

Cloud node nối VLAN 99 vào NIC management của GNS3 compute. Host-only VMware network phải
tắt DHCP để tránh xung đột. Trước mọi thay đổi, snapshot project và export RouterOS bằng
`show-sensitive=no`; không đưa export, image hoặc packet capture vào Git.

Runbook đầy đủ tại
[phase7-syslog-integration.md](../gns3/docs/phase7-syslog-integration.md). Live verification
chỉ bắt đầu sau approval riêng cho thay topology và running-config.

## Performance benchmark Phase 8

Trước benchmark Ubuntu, ghi CPU/RAM/kernel, image digest và dung lượng trống. Start stack
cần đo nhưng không bật Telegram notifications:

```bash
docker compose config --quiet
docker compose up -d --wait rsyslog postgres loki dashboard grafana
python -m app.benchmark --mode compose --duration 10 --repetitions 3
```

Runner không tự start/stop stack để environment không thay đổi giữa repetition. Artifact
nằm trong `artifacts/benchmarks/<run-id>/`; copy CSV/manifest/SVG sang nơi lưu evidence đã
kiểm soát, không copy raw spool. Theo dõi disk vì benchmark mặc định ba repetition tạo
48.000 raw event và không xóa evidence cũ.

Nếu processing throughput thấp hơn ingress, dừng tăng tải, ghi drain time và resource
samples. Không tăng RAM tùy tiện hoặc thêm broker trước khi profile per-event transaction.
Sau test chỉ `docker compose stop` service cần thiết; không dùng `down -v`.

## Rollback principle

Mỗi phase phải giữ schema/data backward-compatible hoặc có migration được test. Rollback container không được tự động xóa volume. Raw spool và database phải được snapshot trước mọi migration không đảo ngược.
