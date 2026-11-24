# Kiến trúc N4.2

## Mục tiêu và trạng thái

N4.2 thu nhận Syslog từ thiết bị mạng, Loghub và Python Syslog Generator. Mục tiêu triển
khai lab là Ubuntu Server 2 vCPU, khoảng 5,3 GiB RAM, chạy Docker Compose. Chuỗi OSPF
cho hai router MikroTik được kiểm thử bằng envelope mô phỏng từ processor đến Loki,
PostgreSQL, Custom Dashboard và Telegram giả lập. Syslog live R1–R2, Grafana runtime
trong Compose và benchmark Ubuntu cần xác nhận riêng.

```text
GNS3 / Loghub / Python Generator
              |
              v
       rsyslog ingestion  ----> raw.log
              |
        processor.jsonl
              |
              v
 Python parse -> normalize -> correlate
              |                    |
              v                    v
            Loki       SQLite journal -> PostgreSQL
              |                    |
              v                    +--> FastAPI/Jinja (queue, evidence, ACK, Resolve)
            Grafana                +--> Telegram (optional)
```

API sự kiện và liên kết điều tra từ Custom Dashboard cũng truy vấn Loki.

## Topology lab đã chốt

R1 và R2 đều là MikroTik CHR chạy RouterOS v7. Hai router thiết lập OSPFv2 Area 0.
Cisco IOSvL2 là switch quản lý và pfSense là firewall tùy chọn. Subnet transit, địa
chỉ hai đầu, Router ID, interface và IP nguồn Syslog chờ operator xác nhận từ lab.
`10.10.40.0/30` chỉ là đề xuất, chưa được phê duyệt.

| VLAN | Vai trò | Subnet |
| --- | --- | --- |
| 10 | Management / Admin Host | `10.10.10.0/24` |
| 20 | Users / Test Host | `10.10.20.0/24` |
| 30 | Servers | `10.10.30.0/24` |

Các thiết bị gửi Syslog đến rsyslog cổng `5514`. RouterOS dùng UDP cho luồng Syslog
cần nghiệm thu trong lab. Đường đến collector cần khả dụng cả khi adjacency OSPF
bị ngắt trong kiểm thử. Xem [checklist nghiệm thu live](deployment.md#điều-kiện-lab-và-checklist-nghiệm-thu-live).

## Boundary thành phần

| Boundary | Trách nhiệm | Không chịu trách nhiệm |
|---|---|---|
| Sources | Phát syslog có timestamp/source rõ ràng | Retry nghiệp vụ hoặc phân loại |
| rsyslog | UDP/TCP listener, raw spool và envelope JSONL qua hai action queue | Parse theo vendor |
| Python processor | Parse, normalize, match rule, fingerprint, aggregate | Lưu raw log duy nhất |
| SQLite Phase 4 | Aggregate state, event membership, cooldown claim | Full-text raw retention hoặc delivery receipt |
| Loki | Raw/normalized log có nhãn cardinality thấp | Alert lifecycle và transactional outbox |
| Processor SQLite | Byte checkpoint, DLQ, receipt và nhật ký tương quan OSPF có thể dựng lại | Alert lifecycle dùng chung |
| PostgreSQL | Incident state, event references, lịch sử, ACK, resolve và notification outbox | Full-text raw log dài hạn |
| Grafana | Quan sát lưu lượng sự kiện, OSPF Down/Full, bảng phân bố, timeline và điều tra log | Quản lý sự cố |
| Custom Dashboard | Hàng đợi vận hành, bộ lọc, bằng chứng, lịch sử, ACK/Resolve và CSV | Biểu đồ quan sát tổng quát |
| Telegram worker | Rate limit, retry, allowlist, delivery receipt | Là nguồn sự thật của alert |

PostgreSQL Phase 5 giữ aggregate state, acknowledgement và status audit. SQLite hiện hữu vẫn phục vụ dashboard cũ và test nhanh; chưa migration dữ liệu legacy tự động. Loki giữ log searchable, còn rsyslog raw spool vẫn là nguồn replay/bằng chứng gốc.

## Data flow và độ tin cậy

1. Source gửi syslog tới rsyslog qua TCP khi có thể; UDP chỉ dùng cho thiết bị lab không hỗ trợ TCP.
2. rsyslog chuyển mỗi message đến hai action queue độc lập có hỗ trợ đĩa và retry.
   `raw.log` giữ input; `processor.jsonl` giữ metadata gửi/nhận và nội dung để parse.
3. Python worker chỉ nâng byte checkpoint sau khi normalized event đã vào Loki và aggregate/reference
   liên quan đã upsert thành công vào PostgreSQL. Checkpoint, DLQ và correlation state nằm trên volume
   `processor-state`.
4. Lỗi parse đi vào dead-letter stream kèm error code và tham chiếu raw record; không sửa hoặc xóa raw payload.
5. Với OSPF, SQLite ghi observation theo `event_id`. Worker ghi sự kiện vào Loki trước
   khi áp dụng revision vào PostgreSQL. PostgreSQL ghi trạng thái, tham chiếu, lịch sử và
   outbox trong cùng transaction.
6. Nếu ghi PostgreSQL thất bại sau Loki, worker đọc lại record tại cùng offset. Dedup
   theo event ID và revision bảo vệ state nghiệp vụ. Bot claim theo transition và chat.
   Khi kết quả lần gửi đầu mơ hồ, delivery được đánh dấu `uncertain`; kết quả đó cần đối soát.

Raw spool có quyền dành cho service account. Cần kế hoạch rotation/retention phối hợp
checkpoint trước khi vận hành dài hạn. Log thật không được đưa vào Git.

## Event contract

Processor dùng `app/schemas/event.py`. `NormalizedEvent 1.0` giữ contract cũ.
`1.1` dành cho OSPFv2, thêm protocol, Area ID, local/peer router ID, peer IP khi nguồn
cung cấp và hai trạng thái adjacency. Interface dùng `interface_name` có sẵn. Loki giữ cả
hai version; `GET /api/v1/events` mặc định trả `1.0`, `include_ospf=true` trả cả hai.
Demo legacy vẫn dùng schema riêng tại [alert_schema.md](alert_schema.md).

Quy tắc versioning:

- Patch không đổi contract wire; chỉ sửa tài liệu/validation tương thích.
- Minor thêm field optional với default và consumer cũ phải bỏ qua an toàn.
- Major thay đổi/đổi nghĩa field; producer và consumer chạy song song trong cửa sổ migration.
- Raw input luôn bất biến; migration chỉ tạo normalized representation mới.

## Dedup và aggregation

Phase 4 dùng `NormalizedEvent.event_id` làm idempotency key. Rule YAML mặc định nhóm Link Up/Down theo thiết bị, giao diện, họ `link_state` và tumbling window UTC 60 giây có biên cuối loại trừ. Aggregate giữ `count`, `first_seen`, `last_seen`, severity lớn nhất và tập event type gốc; bảng membership giữ raw message cùng normalized JSON của mọi event duy nhất. Replay cùng `event_id` không tăng count lần hai.

OSPF dùng scope, Area ID, cặp Router ID và định danh link. Mỗi đầu đã báo Down cần một
Full đáng tin cậy mới hơn Down mới nhất của đầu đó. Event đến muộn có thể cập nhật lại
projection kỹ thuật. ACK và Resolve thủ công giữ actor, note và history độc lập với
timestamp kỹ thuật. Sự cố đang mở tiếp tục hiện trong queue mặc định sau 24 giờ. Xem
[correlation](correlation.md), [storage](storage.md) và [notification](dashboard_notifications.md).

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

## Quyết định Phase 7 (lịch sử)

Các mục dưới đây mô tả thiết kế và snapshot gốc trước topology hai CHR.

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

Các mục Phase 1–8 bên dưới ghi các mốc gốc của dự án trước khi bổ sung luồng OSPF R1–R2.

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

## Backend vận hành và frontend riêng

- FastAPI phục vụ API vận hành và dashboard Jinja ngay trong cùng tiến trình. Bearer session và
  session cookie vận hành có digest riêng trong PostgreSQL. Dashboard Jinja giữ kiểm tra CSRF
  cho mutation. Role được kiểm tra tại API trước khi trả dữ liệu hoặc sửa trạng thái.
- Processor ghi Loki và lưu xác nhận vào state SQLite trước khi ghi journal correlation.
  PostgreSQL cập nhật incident projection, catalog, registry, observation và rule quản lý trong
  cùng transaction. Catalog dùng `event_id` làm khóa duy nhất. Offset được checkpoint sau khi lưu
  thành công. Replay giữ nguyên lần ghi catalog đầu tiên và quan hệ với registry.
- Device registry khớp từ địa chỉ peer của rsyslog đã được đăng ký, kết hợp vendor khi khai báo.
  Tên thiết bị và IP đọc được trong payload dùng cho phân tích. Event chưa xác nhận có
  `device_id=null`. `last_seen` chỉ cập nhật từ bản ghi gắn với thiết bị.
- Dữ liệu gốc tiếp tục nằm trong spool kiểm soát truy cập và payload chuẩn hóa nằm trong Loki.
  PostgreSQL giữ catalog cho truy vấn, thống kê, registry, rule, session và audit. Các phiên bản
  `NormalizedEvent` 1.0 và 1.1 vẫn đọc được qua API cũ. Catalog phản ánh dữ liệu được processor
  mới ghi và khai báo phạm vi bằng `coverage_start`.
- Topology kết hợp inventory do operator xác nhận với observation của OSPF. Mỗi mapping dùng
  scope, area, cặp Router ID và định danh link. Neighbor thiếu mapping giữ trạng thái chưa xác
  định. Cấu hình ban đầu không khai báo endpoint khi chưa có bằng chứng live.
- Grafana dùng PostgreSQL views chỉ đọc cho KPI và dùng Loki cho truy vấn log kỹ thuật. Dashboard
  summary và báo cáo API dùng chung định nghĩa KPI. Audit hành động bảo mật nằm riêng với event
  logs. [API](api-contract.md), [KPI](kpi-contract.md) và [Grafana](grafana-integration.md).
