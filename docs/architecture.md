# Kiến trúc N4.2

## Mục tiêu và trạng thái

Kiến trúc đích thu nhận log nhẹ từ GNS3, Loghub và Python Syslog Generator; bảo toàn raw log; chuẩn hóa bằng Python; lưu log trong Loki; quản lý trạng thái cảnh báo trong PostgreSQL khi cần; trình bày qua Grafana và Custom Dashboard; gửi thông báo Telegram. Toàn bộ chạy bằng Docker Compose trên Ubuntu Server 2 vCPU, khoảng 5,3 GiB RAM.

Kiến trúc hiện hành nối Custom Dashboard và Telegram vào Loki/PostgreSQL, đồng thời provision Grafana cho operational log visualization. FastAPI, SQLite compatibility, rsyslog, parser và correlation vẫn được giữ. Hệ thống tập trung quản lý sự kiện mạng và không triển khai chức năng SOC/SIEM tổng quát.

```text
GNS3 / Loghub / Python Generator
              |
              v
       rsyslog ingestion  ----> raw spool bền vững
              |
              v
 Python parse -> normalize -> correlate -> aggregate
              |                    |
              v                    v
            Loki       SQLite -> PostgreSQL state
              |                    |
              +---------+----------+
                        v
             Grafana / Custom Dashboard
                        |
                        v
                     Telegram
```

## Boundary thành phần

| Boundary | Trách nhiệm | Không chịu trách nhiệm |
|---|---|---|
| Sources | Phát syslog có timestamp/source rõ ràng | Retry nghiệp vụ hoặc phân loại |
| rsyslog | UDP/TCP listener, ghi raw spool trước, chuyển tin cậy tới worker | Parse theo vendor |
| Python processor | Parse, normalize, match rule, fingerprint, aggregate | Lưu raw log duy nhất |
| SQLite Phase 4 | Aggregate state, event membership, cooldown claim | Full-text raw retention hoặc delivery receipt |
| Loki | Raw/normalized log có nhãn cardinality thấp | Alert lifecycle và transactional outbox |
| Processor SQLite | Byte checkpoint, DLQ, health và correlation trace cục bộ | Alert lifecycle dùng chung |
| PostgreSQL | Aggregate state, acknowledgement, notification outbox | Full-text raw log dài hạn |
| Dashboard/Grafana | Điều tra, KPI, visualization | Ingestion hoặc notification delivery |
| Telegram worker | Rate limit, retry, allowlist, delivery receipt | Là nguồn sự thật của alert |

PostgreSQL Phase 5 giữ aggregate state, acknowledgement và status audit. SQLite hiện hữu vẫn phục vụ dashboard cũ và test nhanh; chưa migration dữ liệu legacy tự động. Loki giữ log searchable, còn rsyslog raw spool vẫn là nguồn replay/bằng chứng gốc.

## Data flow và độ tin cậy

1. Source gửi syslog tới rsyslog qua TCP khi có thể; UDP chỉ dùng cho thiết bị lab không hỗ trợ TCP.
2. rsyslog ghi từng message vào raw spool trước khi forward. Action queue dùng disk-assisted queue, retry vô hạn có backoff và checkpoint riêng.
3. Python worker chỉ nâng byte checkpoint sau khi normalized event đã vào Loki và aggregate/reference
   liên quan đã upsert thành công vào PostgreSQL. Checkpoint, DLQ và correlation state nằm trên volume
   `processor-state`.
4. Lỗi parse đi vào dead-letter stream kèm error code và tham chiếu raw record; không sửa hoặc xóa raw payload.
5. Loki nhận bản raw và normalized theo batch. PostgreSQL, nếu được bật, giữ alert state/outbox để Telegram có at-least-once delivery.
6. Consumer phải idempotent vì replay có thể tạo delivery trùng.

Raw spool sẽ có rotation theo dung lượng/thời gian, quyền chỉ dành cho service account và retention có cấu hình. Log thật không được đưa vào Git.

## Event contract

Contract hiện hành là `schema_version: "1.0"` tại `app/schemas/alert.py`, mô tả chi tiết trong [alert_schema.md](alert_schema.md) và JSON Schema tại [alert.schema.json](alert.schema.json). Event gồm identity, UTC timestamps, source/device/rule/network, severity, MITRE, lifecycle state, `raw_log`, `alert_id` và `dedup_key`.

Quy tắc versioning:

- Patch không đổi contract wire; chỉ sửa tài liệu/validation tương thích.
- Minor thêm field optional với default và consumer cũ phải bỏ qua an toàn.
- Major thay đổi/đổi nghĩa field; producer và consumer chạy song song trong cửa sổ migration.
- Raw input luôn bất biến; migration chỉ tạo normalized representation mới.

## Dedup và aggregation

Phase 4 dùng `NormalizedEvent.event_id` làm idempotency key. Rule YAML mặc định nhóm Link Up/Down theo thiết bị, giao diện, họ `link_state` và tumbling window UTC 60 giây có biên cuối loại trừ. Aggregate giữ `count`, `first_seen`, `last_seen`, severity lớn nhất và tập event type gốc; bảng membership giữ raw message cùng normalized JSON của mọi event duy nhất. Replay cùng `event_id` không tăng count lần hai.

Notification worker phải claim cooldown atomically trước khi gọi Telegram. Claim được persist nên restart không làm mất dedup state. Chi tiết group key, cửa sổ, trace và failure recovery nằm trong [correlation.md](correlation.md).

## Quyết định Phase 1

- Giữ modular monolith để tái sử dụng frontend/backend và tránh network hop sớm.
- Dùng Python 3.12 thống nhất local, container và CI.
- Tách `Dockerfile.dev` có reload khỏi Dockerfile production không reload.
- Canonical Compose là `compose.yaml`; service tùy chọn dùng profiles.
- CI không có quyền ghi repository, không deploy và không nhận production secrets.
- Không đưa Loki, Grafana, PostgreSQL hoặc rsyslog vào Compose cho đến phase tương ứng.

## Quyết định Phase 2

- rsyslog nhận TCP/UDP trên port nội bộ 5514 và ghi nguyên `$rawmsg` trước mọi parsing.
- Queue disk-assisted và raw spool dùng named volume riêng để restart không làm mất dữ liệu.
- Python generator hỗ trợ RFC 5424 sequence ID, pacing và replay Loghub theo từng dòng.
- Không thêm Kafka/Redis khi mới có một sink và chưa có benchmark chứng minh cần broker.
- Data flow, failure semantics và recovery được mô tả trong [syslog_collection.md](syslog_collection.md).

## Quyết định Phase 3

- Tách normalized network event khỏi alert lifecycle hiện hữu; cả hai đều có version độc lập.
- Chỉ parser format có fixture và tài liệu vendor; không suy đoán Port Flap/Neighbor Down.
- Raw message bất biến trong event thành công; oversized/multiline input bị từ chối trước regex.
- Unknown và malformed là kết quả dữ liệu, không phải exception làm dừng worker.
- Coverage và assumptions nằm trong [parsing.md](parsing.md).

## Quyết định Phase 4

- Dùng fixed UTC event-time window để kết quả không phụ thuộc arrival order và ổn định qua replay/restart.
- Link Up/Down được cấu hình thành một event family `link_state`; event type gốc vẫn nằm trong trace.
- Ghi raw membership và cập nhật aggregate trong cùng SQLite transaction; không thêm broker hay database mới.
- Cooldown notification là atomic persisted claim. Transactional outbox được hoãn tới khi có yêu cầu delivery/benchmark rõ ràng.
- Semantics và acceptance test nằm trong [correlation.md](correlation.md).

## Quyết định Phase 5

- Loki chạy single-binary/filesystem TSDB để tiết kiệm RAM; label chỉ dùng field cardinality thấp.
- PostgreSQL lưu aggregate/lifecycle/event reference, không lưu lại raw payload.
- FastAPI hiện hữu được tái sử dụng; API JSON dùng session và CSRF thay vì tạo auth stack mới.
- SQL migration forward-only có checksum và advisory lock; startup không xóa database khi lỗi.
- Write coordinator ghi Loki trước PostgreSQL; replay được che duplicate theo `event_id`.
- API và schema được mô tả tại [api.md](api.md) và [storage.md](storage.md).

## Quyết định Phase 6

- Custom Dashboard tái sử dụng template/session/CSRF hiện hữu; `DASHBOARD_BACKEND` chọn legacy hoặc operational.
- Loki cung cấp normalized event stream; PostgreSQL cung cấp aggregate stats, filter và lifecycle.
- Grafana datasource/dashboard được provision read-only từ Git, không cấu hình tay trong UI.
- Telegram claim atomically theo severity, event count và cooldown; update message đã lưu thay vì gửi bản trùng.
- Semantics và giới hạn last-mile nằm trong [dashboard_notifications.md](dashboard_notifications.md).

## Quyết định Phase 7

- Giữ CHR và host hiện hữu; chỉ thay built-in Switch1 bằng managed IOSvL2 hợp pháp sau
  approval vì built-in switch không có control plane/Syslog.
- Dùng VLAN 99 riêng cho management/Syslog và Cloud bridge tới NIC lab của Ubuntu;
  collector bind đúng `10.10.99.10`, không bind public interface.
- pfSense là nguồn tùy chọn và chỉ bật khi test firewall để giảm tài nguyên GNS3.
- Live, replayed và synthetic evidence được ghi riêng; replay/generator không chứng minh
  thiết bị live đã forward thành công.
- Format live mới phải được capture, khử dữ liệu nhạy cảm và thêm fixture trước khi mở
  rộng parser. Không suy đoán prefix/timestamp vendor.
- Topology, routing và acceptance runbook nằm tại
  [Phase 7 GNS3 integration](../gns3/docs/phase7-syslog-integration.md).

## Lộ trình tám phase

1. Repository and Development Foundation.
2. Syslog collection, raw spool và replay — implemented.
3. Multi-vendor parsing và Normalized Event 1.0 — implemented.
4. Event correlation, aggregation và notification cooldown — implemented.
5. Loki, PostgreSQL state và Backend API — implemented.
6. Custom Dashboard, Grafana và Telegram integration — implemented.
7. GNS3 managed-device Syslog integration — review-only design/static audit implemented;
   live acceptance pending approval.
8. Performance benchmark, deployment/testing/demo documentation — runner/local preflight
   implemented; Ubuntu Compose benchmark pending.

## Quyết định Phase 8

- Không gọi local loopback là kết quả Ubuntu; mọi CSV ghi rõ environment/mode/basis.
- Giữ số đo Phase 8 cũ là ingress/batch preflight; continuous raw-spool worker mới phải được benchmark
  riêng trên Ubuntu trước khi dùng làm kết quả triển khai.
- Dùng absolute-deadline pacing, exact payload counting và raw-spool byte offset.
- CPU/RAM runner dùng process metrics; Compose mode dùng read-only `docker stats`, không
  mount Docker socket vào container.
- Giữ artifact ngoài Git, nhưng commit methodology và schema CSV `NOT_RUN` cho Ubuntu.
- Bottleneck preflight là per-event SQLite transaction; chưa có bằng chứng cần Kafka hoặc Redis.

## Quyết định processing pipeline trước deployment

- rsyslog giữ `$rawmsg` bất biến trong `raw.log` và đồng thời tạo envelope JSONL version `1.0` gồm
  thời điểm nhận, host/IP nguồn và raw message cho processor. Hai output dùng disk-assisted queue riêng.
- Processor đọc theo byte offset, chỉ nhận record kết thúc newline và không checkpoint partial record.
- Malformed/unknown là poison record: ghi DLQ và checkpoint trong cùng transaction SQLite. Lỗi
  correlation/Loki/PostgreSQL giữ nguyên checkpoint để retry.
- `NormalizedEvent.event_id`, correlation membership PK, Loki query dedup và PostgreSQL
  `alert_event_refs(event_id)` tạo exactly-once logic trên delivery at-least-once; không có distributed
  transaction giữa Loki và PostgreSQL.
- Chỉ chạy một processor active cho một spool. `processor-state`, `syslog-raw`, PostgreSQL và Loki đều
  phải nằm trong kế hoạch backup; không xóa volume để xử lý lỗi.
