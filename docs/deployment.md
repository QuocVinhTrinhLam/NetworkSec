# Triển khai và vận hành

## Phạm vi hiện tại

Tài liệu này hướng dẫn operator triển khai thủ công và nghiệm thu Syslog lab. Luồng OSPF
đã được kiểm thử phần mềm với bản ghi spool mô phỏng. Ubuntu Compose và tích hợp live
GNS3 R1–R2 vẫn cần nghiệm thu tại môi trường đích. Grafana phục vụ giao diện giám sát.
Tích hợp và thao tác vận hành dùng API JSON với bearer token.
[Checklist Ubuntu và GNS3](ubuntu-deployment-checklist.md)

## Triển khai OSPF trên Ubuntu

### Cấu hình môi trường

Điền `.env` từ `.env.example` trong checkout đã review. Giữ file ở quyền `0600`.
Với deployment đang chạy, giữ tên Compose project, cấu hình và named volumes hiện hữu.

| Thành phần | Biến và giá trị triển khai |
|---|---|
| PostgreSQL | `POSTGRES_PASSWORD` bắt buộc. Compose ghép password vào DSN libpq dạng key/value; dùng giá trị mạnh dạng hex để tránh ký tự cần escape. `POSTGRES_DB` và `POSTGRES_USER` mặc định `networksec`. Giữ `POSTGRES_BIND_HOST=127.0.0.1`, port mặc định `5432`. |
| rsyslog | `SYSLOG_BIND_HOST` mặc định `127.0.0.1`. Khi nhận log từ GNS3, đặt thành **IP NIC lab đã xác nhận trên Ubuntu**. `SYSLOG_TCP_PORT` và `SYSLOG_UDP_PORT` đều mặc định `5514`. |
| Processor | `PROCESSOR_SOURCE_TIMEZONE` mặc định `UTC`. Đồng bộ đồng hồ R1, R2 và Ubuntu; đặt timezone khớp timestamp không có offset của nguồn. Chuẩn hóa các nguồn timestamp kiểu này về cùng timezone trước khi thu nhận. |
| Loki | `LOKI_BIND_HOST=127.0.0.1`, port mặc định `3100`. Các container truy cập `http://loki:3100`. |
| Grafana | `GRAFANA_ADMIN_PASSWORD` bắt buộc khi bật Grafana. `GRAFANA_ADMIN_USER` mặc định `admin`; giữ `GRAFANA_BIND_HOST=127.0.0.1`, port mặc định `3000`. |
| API | `SESSION_SECRET` ngẫu nhiên, duy nhất và dài ít nhất 32 ký tự. Tạo `ADMIN_PASSWORD_HASH` qua `python -m app.password_hash`. Giữ `BIND_HOST=127.0.0.1` và `API_PORT=8000`. Dùng `SESSION_HTTPS_ONLY=true` để bật HSTS khi dùng HTTPS. |
| Telegram tùy chọn | `TELEGRAM_BOT_TOKEN` và `ALLOWED_CHAT_IDS` bật bot. Đặt `GRAFANA_PUBLIC_URL` thành URL mà người nhận truy cập được. `TELEGRAM_MIN_SEVERITY` mặc định `medium`. |

`SYSLOG_BIND_HOST` chỉ điều khiển IP host publish cho TCP và UDP; cả hai listener trong
container vẫn nghe cổng `5514`. NIC lab và đường đi từ R1/R2 cần được chuẩn bị thủ công.
Kiểm tra IP bằng `ip -brief address` trên Ubuntu. Chỉ dùng mạng lab dành riêng cho
Syslog plaintext. Giữ các cổng quản trị trên loopback và dùng đường truy cập quản trị đã duyệt.

### Các bước operator thực hiện

1. Xác nhận Docker Engine/Compose v2 có sẵn, cổng khả dụng và đủ dung lượng lưu trữ.
   Sao lưu PostgreSQL và snapshot nhất quán các volume cần bảo toàn trước khi nâng cấp.
   Giữ ít nhất `syslog-raw`, `syslog-queue`, `processor-state`, `postgres-data`,
   `loki-data`, `grafana-data` và `monitor-data` trong kế hoạch sao lưu.
2. Trước khi build, dùng log đã ghi nhận để xác nhận `device_name`, Router ID,
   Area ID và `interface_name` của hai CHR. Điền vào `ospf.links` trong
   `config/correlation_rules.yaml` để correlation hợp nhất hai phía. Mặc định danh
   sách này rỗng. [Ví dụ mapping](correlation.md#định-danh-adjacency).
3. Kiểm tra manifest tĩnh, sau đó chạy stack từ thư mục checkout trên Ubuntu.
   Các lệnh dưới đây dành cho lần triển khai thủ công đã được phê duyệt.

```bash
docker compose --env-file .env --profile notifications config --quiet
docker compose --env-file .env up -d --build --wait
docker compose ps
curl -fsS http://127.0.0.1:3100/ready
curl -fsS http://127.0.0.1:3000/api/health
curl -fsS http://127.0.0.1:8000/health
docker compose exec -T processor python -m app.processor.healthcheck
```

Đăng nhập qua API, xác nhận `/api/v1/storage/health` trả cả Loki và PostgreSQL
`ready`. Healthcheck Compose của Loki kiểm tra cấu hình; `/ready` kiểm tra runtime.
Các container ứng dụng áp dụng migration `001`–`005` theo thứ tự. Giữ checksum của
migration đã chạy. Nếu nâng cấp lỗi, giữ volumes, xem log đã khử dữ liệu nhạy cảm
và dùng quy trình restore đã kiểm thử nếu cần.

Chỉ khi đã duyệt chat đích và thông báo thật, operator có thể bật bot:

```bash
docker compose --env-file .env --profile notifications up -d --build --wait bot
```

### Điều kiện lab và checklist nghiệm thu live

- [ ] Kiểm tra R1 và R2 là MikroTik CHR chạy RouterOS v7, switch là Cisco IOSvL2,
  và VLAN 10/20/30 khớp [topology đã chốt](architecture.md#topology-lab-đã-chốt).
  Xác nhận subnet và địa chỉ transit thực tế, Area ID `0.0.0.0`, Router ID riêng
  biệt và adjacency ở Full trên cả hai đầu. pfSense là tùy chọn.
- [ ] Kiểm tra mỗi CHR gửi Syslog qua UDP tới IP NIC lab của Ubuntu và cổng `5514`.
  Giữ đường tới collector khả dụng trong lúc thử gián đoạn adjacency. Ghi lại
  phiên bản RouterOS, logging format, topics/prefix, IP nguồn nhận tại collector,
  hostname trong header, timestamp/timezone, `received_at`, `source_host`,
  `raw_message` và `parse_message` cho Down và Full của từng đầu. Giữ mẫu gốc trong
  vùng kiểm soát và khử dữ liệu nhạy cảm trước khi thêm fixture.
  [Tài liệu logging RouterOS](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/#send-the-log-to-a-syslog-server).
- [ ] Thu mẫu IOSvL2 theo đúng image lab từ các sự kiện interface và config đã duyệt.
  Đối chiếu header timestamp và mnemonic với parser Cisco hiện hữu. Khi có pfSense,
  xác nhận đường gửi và mẫu IPv4 `filterlog` block nếu thiết bị tham gia bài test.
- [ ] Trong cửa sổ test được duyệt, tạo một lần gián đoạn transit. Đối chiếu raw spool,
  envelope, checkpoint/DLQ và Loki. Hai Down của cùng link phải hiện như hai observation
  trong OSPF Observability và một incident ID trong Incident Operations. Bản replay cùng
  event ID không được tăng số evidence duy nhất.
- [ ] ACK incident bằng tài khoản vận hành và ghi note. Sau khi phục hồi transit, kiểm
  tra INIT/2-WAY/EXSTART/EXCHANGE/LOADING và Full cũ không đóng incident. Nếu hai đầu đã
  báo Down, chỉ resolve khi mỗi đầu có Full tin cậy mới hơn Down tương ứng.
- [ ] Sau Full xác nhận, kiểm tra cùng incident ID chuyển `resolved` với nguồn
  `ospf_recovery`, timestamp kỹ thuật, history, ACK và note còn nguyên. Đối chiếu cả
  hai nguồn log trong Grafana và bằng chứng từ API. Nếu operator đã
  resolve thủ công, telemetry phục hồi chỉ cập nhật phần kỹ thuật.
- [ ] Restart processor có kiểm soát trên môi trường test, replay input trùng và quan sát
  không phát sinh incident hoặc transition trùng. Lặp một lần Down sau recovery để xác
  nhận incident mới. Nếu bật bot test đã duyệt, mỗi chat chỉ có một thẻ Down và thẻ đó
  được cập nhật khi recovery được xác nhận.

`tests/test_gns3_phase7.py` mô tả snapshot gốc tám node và bảy link. Kết quả snapshot
chỉ xác nhận metadata đã lưu. [Runbook GNS3 gốc](../gns3/docs/phase7-syslog-integration.md)
là bối cảnh lịch sử cho đường Syslog management. Dùng checklist trên để nghiệm thu
topology hai CHR đã chốt.

### Ngân sách tài nguyên

Core Compose gồm sáu service với tổng memory limit khai báo khoảng `1.536 MiB`. Bot
thêm `128 MiB`; mock và generator tùy chọn thêm `64 MiB` mỗi service khi chạy. Đây là
giới hạn container, chưa gồm Ubuntu, Docker, GNS3 VM, node mạng và Windows 16 GB. Đo RAM,
CPU, disk, backlog và độ trễ parse đến alert ở môi trường đích. Giữ một processor cho
mỗi spool; kiểm soát tăng trưởng raw spool và lịch sử adjacency. Các tính năng OSPF
dùng lại toàn bộ service hiện hữu.

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
docker compose --file compose.yaml up -d --build --wait
docker compose --file compose.yaml ps
docker compose --file compose.yaml logs --tail=200 api
```

`config --quiet` được dùng để validation mà không in resolved environment có thể chứa secret. Không dùng
`docker compose config` không kèm `--quiet` trong log CI hoặc khi chia sẻ màn hình. Trước lần chạy đầu
phải điền `POSTGRES_PASSWORD`, `SESSION_SECRET` và `ADMIN_PASSWORD_HASH` trong `.env`; Compose không chứa
giá trị thật.

Bot Telegram chỉ chạy khi có token thật và allowlist chat trong `.env`:

```bash
docker compose --profile notifications up --build bot
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

Trước replay dữ liệu lưu trữ, kiểm tra giới hạn timestamp của Loki. Loki 3.7.0 với cấu
hình hiện tại dùng giới hạn mặc định một tuần cho mẫu cũ và có giới hạn riêng cho
ghi sai thứ tự trong một stream. Nếu Loki từ chối record, processor giữ checkpoint
để retry. Giữ timestamp gốc và lập kế hoạch replay riêng cho backlog vượt giới hạn.

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

Processor giữ SQLite correlation trên volume `processor-state`. Dockerfile đóng gói
`config/correlation_rules.yaml` vào image, được đọc từ filesystem container read-only.
Thay mapping đã review cần build lại image. SQLite legacy ở `monitor-data` phục vụ demo.

Khi backup, cần snapshot nhất quán file database cùng WAL/SHM hoặc dừng writer ngắn trước khi copy. Không xóa database để xử lý lỗi schema. Sau restore, có thể replay raw spool: unique `event_id` ngăn count tăng lại, còn aggregate/cooldown đã commit tiếp tục qua restart.

Trước khi đổi rule đang chạy, lưu bản rule cũ cùng backup. Thay `rule_id`, `group_by` hoặc `window_seconds` làm thay đổi aggregate identity; replay với rule mới có thể tạo nhóm mới và phải được xem là migration có chủ đích.

## Storage Phase 5

Tạo `.env` cục bộ và điền `POSTGRES_PASSWORD` ngẫu nhiên, không commit hoặc đưa password lên command line. Xác minh rồi khởi động:

```bash
docker compose config --quiet
docker compose up --build postgres loki api
docker compose ps
```

`postgres-data` và `loki-data` là named volumes. Không dùng `down -v`. PostgreSQL và Loki bind `127.0.0.1` để test/điều tra local; trên Ubuntu không đổi thành `0.0.0.0`. Loki không có auth tích hợp, còn PostgreSQL chỉ nên nhận kết nối từ Compose network/loopback.

FastAPI chạy migration PostgreSQL khi lifespan bắt đầu. Nếu migration lỗi, đọc log dashboard, sửa migration mới hoặc restore backup; không sửa checksum migration đã áp dụng và không xóa volume.

Chạy integration test storage khi stack healthy. Nạp `POSTGRES_DSN` và `LOKI_URL` từ môi trường bảo vệ trước, không đặt secret trong lệnh hoặc shell history:

```bash
RUN_STORAGE_INTEGRATION=1 python -m pytest -m storage_integration
```

Không lưu command có password vào shell history trên máy dùng chung; ưu tiên export từ file permission 0600 hoặc secret manager khi deploy thật.

## Grafana và Telegram

Đặt `GRAFANA_ADMIN_PASSWORD`, `TELEGRAM_BOT_TOKEN` và `ALLOWED_CHAT_IDS` trong `.env` được bảo vệ. Không dùng password Grafana mặc định. Khởi động Grafana cùng storage:

```bash
docker compose up -d --build --wait
docker compose --profile notifications up --build bot
```

Grafana nạp dashboard và datasource Loki từ `infra/grafana/`. Thiết lập datasource PostgreSQL
với tài khoản chỉ đọc sau khi migration `010` hoàn tất. Giữ `grafana-data` khi tạo lại container.
[Hướng dẫn cấu hình datasource](grafana-integration.md).

Compose cấp 512 MiB RAM cho Grafana và dùng plugin Loki có sẵn trong image. Kiểm tra Grafana từ host tại `http://127.0.0.1:3000/api/health`. Nếu healthcheck báo lỗi, xem log khởi động bằng `docker compose logs --tail 100 grafana`.

Grafana, PostgreSQL, Loki và API bind loopback mặc định. Dùng SSH tunnel hoặc reverse proxy TLS đã review khi truy cập từ máy Windows host tới Ubuntu VM.

Bot PostgreSQL chạy các migration hiện có, gồm delivery outbox OSPF trong `005`, trước loop.

## Nâng cấp Grafana-only

Trước khi chuyển từ `5527465`, dùng checkout cũ với cùng Compose project để chạy
`docker compose stop dashboard`. Service `api` dùng cùng cổng host mặc định. Có thể tiếp tục
dùng `DASHBOARD_PORT` làm fallback khi chưa đặt `API_PORT`. Giữ tên project và các named volume
hiện có. Sau khi build và khởi động cấu hình mới, kiểm tra migration `010` rồi bổ sung quyền
đọc ba view Grafana cho role reader hiện có. Grafana Loki và dashboard KPI hiện có tiếp tục dùng
cùng datasource UID. [Quyền PostgreSQL của Grafana](grafana-integration.md#configure-postgresql-access).

Nếu rollback ứng dụng, dừng `api` từ checkout mới trước khi khởi động lại `dashboard` từ bản cũ.
Migration `010` chỉ thêm view. Giữ dữ liệu và lịch sử migration, rồi kiểm tra phiên bản cũ trên
bản sao thử nghiệm trước khi rollback. Bearer session đã cấp có thể tiếp tục dùng khi cấu hình
và database giữ nguyên. Các client cũ cần đổi `/api/v1/dashboard/summary` thành `/api/v1/reports/summary`.

## Backend operational API

API và processor áp dụng lần lượt migration PostgreSQL khi khởi động. Các migration mới
bổ sung registry, event catalog, session, audit, rule quản lý và view KPI. Trước khi nâng cấp,
backup PostgreSQL cùng các volume log/checkpoint theo quy trình lưu trữ hiện có. Hai dịch vụ
dùng cùng bộ migration đã version hóa. Giữ nguyên volume nếu cần rollback phiên bản ứng dụng
và đánh giá tương thích schema trên môi trường cô lập trước khi rollback.

1. Điền giá trị thích hợp trong môi trường triển khai. Dùng `.env.example` để tra tên biến.
   `SESSION_SECRET` cần duy nhất, dài ít nhất 32 ký tự cho Compose production.
   `FRONTEND_ORIGINS` là danh sách origin phân cách bằng dấu phẩy và `TRUSTED_HOSTS` giữ
   `127.0.0.1` để healthcheck hoạt động. Khi dùng HTTPS, bật `SESSION_HTTPS_ONLY=true`.
2. Xác thực cấu hình bằng `docker compose config --quiet`. Trên môi trường đã được duyệt,
   chạy `docker compose up -d --build --wait`.
   Xem `docker compose ps`, `curl -fsS http://127.0.0.1:8000/health` và
   `docker compose exec -T processor python -m app.processor.healthcheck`.
3. Đăng nhập API qua tài khoản bootstrap rồi tạo tài khoản Admin, Analyst hoặc Viewer
   theo [API contract](api-contract.md#sessions-and-users). Mặc định bearer session hết hạn
   sau 3.600 giây. Chỉ khai báo thiết bị và source address đã được xác minh ở collector.
4. Ghi inventory vật lý/segment tại `config/topology.yaml`. Mỗi node gồm tên và loại, mỗi
   link gồm ID ổn định, tên hai node, `link_type` và interface nếu đã biết. Hai node của
   link phải được khai báo trong inventory. Cặp OSPF dùng `ospf.links` trong
   `config/correlation_rules.yaml`. Bổ sung scope/area, Router ID, tên reporter và
   interface dựa trên kết quả xác nhận của operator. Đặt `source_addresses` tại từng endpoint
   để mapping kiểm tra địa chỉ peer của collector đối với các nguồn đã xác minh.
   API và processor phải đọc cùng cấu hình correlation. Với cấu hình được đóng gói trong
   image, cập nhật bằng `docker compose up -d --build processor api` trong deployment
   đã được duyệt. [Checklist live](evidence/gns3-validation/README.md).
5. Đặt `GRAFANA_PUBLIC_URL` theo đường dẫn mà trình duyệt truy cập được. Nếu dùng reverse
   proxy subpath, bao gồm subpath trong base URL. Mặc định UID là `network-event-kpis`.
   `GRAFANA_VARIABLE_MAPPING` ánh xạ tên filter API sang biến dashboard, gồm
   `device`, `device_id`, `severity`, `category`, `incident` với dashboard KPI.
   [Cài đặt datasource và phân quyền Grafana](grafana-integration.md).

Các rule quản lý nhận event từ parser đã xác minh. Mặc định rule login failure, firewall deny,
configuration change và port flap dựa trên ngưỡng sự kiện trong cửa sổ UTC. Mỗi lần đổi
definition tạo revision mới cho các sự kiện tiếp theo. Kiểm tra rule bằng fixtures qua API
test trước khi bật và theo dõi audit. Cấu hình built-in interface và OSPF nằm trong YAML.
Interface Up mới hơn có thể đóng sự cố Down của cùng interface và nguồn thiết bị. Bản ghi Up
trùng thời điểm hoặc từ nguồn khác không đóng sự cố. Sự cố đã resolve thủ công giữ nguyên.
Trạng thái `stale` hiện là tín hiệu telemetry theo interval của thiết bị. Rule báo sự cố do
thiếu log cần xác nhận collector đang khỏe và thiết bị từng được quan sát. Sự kiện khởi động
lại và các loại lỗi chưa có fixture/parser cần nguồn dữ liệu xác nhận trước khi thêm rule.
[Hợp đồng rule API](api-contract.md#correlation-rules).

Catalog bắt đầu ghi khi processor mới chạy. Loki vẫn phục vụ các log lịch sử còn trong
retention. Xem `coverage_start` khi đối chiếu số liệu sau nâng cấp. [KPI](kpi-contract.md).
Backup PostgreSQL trước migration và giữ delivery state khi nâng cấp.

## GNS3 Syslog Phase 7 (lịch sử)

Phần này ghi lại thiết kế Phase 7. IP và VLAN bên dưới thuộc môi trường gốc.

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
docker compose up -d --wait
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
