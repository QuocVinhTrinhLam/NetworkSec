# Storage và vòng đời alert

## Boundary và write path

```text
NormalizedEvent 1.0 / 1.1 ──> LokiLogStorage ──> Loki filesystem/TSDB
        |
        +─ correlated AggregatedAlert ──> PostgresAlertStorage
                                         ├─ aggregated_alerts
                                         └─ alert_event_refs(event_id)
```

`StorageWriter` ghi event searchable vào Loki trước, sau đó upsert aggregate và event reference vào PostgreSQL. PostgreSQL không nhân bản raw payload. Raw spool rsyslog vẫn là bằng chứng gốc/replay source.

Nếu Loki thành công nhưng PostgreSQL thất bại, worker retry cùng input: PostgreSQL upsert/idempotency không tăng state sai; Loki có thể chứa delivery lặp nhưng query adapter loại trùng theo `event_id`. Nếu Loki thất bại, PostgreSQL chưa được publish nên alert state không trỏ tới log chưa tồn tại.

Không có distributed transaction giữa Loki và PostgreSQL. Processing worker đã triển khai byte
checkpoint cục bộ: chỉ advance sau Loki push và PostgreSQL upsert; crash ở khoảng giữa sẽ replay cùng
`event_id`. Vì các adapter downstream idempotent về mặt logic, aggregate/reference không double-count;
Loki có thể nhận physical delivery lặp nhưng query adapter loại trùng. Không dùng Kafka/Redis cho quy mô
lab này.

## Loki

- Version Compose: `grafana/loki:3.7.0`, single binary `target=all`.
- Storage: TSDB schema v13 và filesystem trên named volume `loki-data`.
- Labels: `job`, `schema_version`, `vendor`, `event_type`, `severity`.
- `device_name`, `interface_name`, `event_id`, raw message nằm trong JSON line, không dùng làm label.
- API adapter dùng `/loki/api/v1/push`, `/loki/api/v1/query_range` và `/ready`.
- Embedded query cache giới hạn 32 MiB; analytics tắt.

Loki không có authentication tích hợp trong cấu hình này. Port host chỉ bind `127.0.0.1`; không đổi thành public interface. Dashboard truy cập qua Compose DNS `http://loki:3100`.

## PostgreSQL schema

Migration được lưu bất biến tại `migrations/postgresql/`. Runner tạo `schema_migrations(version, checksum, applied_at)`, giữ advisory lock trong transaction và từ chối nếu checksum của migration đã áp dụng bị thay đổi.

### `aggregated_alerts`

| Nhóm | Cột chính |
|---|---|
| Identity | `aggregate_id` PK, `schema_version`, `rule_id`, `event_family`, `group_key JSONB` |
| Group | `device_name`, `interface_name`, `event_types JSONB` |
| Window | `window_start`, `window_end`, `first_seen`, `last_seen`, `event_count` |
| Priority | `severity` với CHECK low/medium/high/critical |
| Lifecycle | `status`, acknowledgement fields, status audit fields, `note` |
| Notification | cooldown, last notification, notification count |
| Audit | `created_at`, `updated_at` |

Indexes hỗ trợ sort/filter theo time, severity, status, device và GIN event types. Constraint kiểm tra window/time order, count, enum và JSON shape.

Upsert link-state giữ severity và count cao nhất, đồng thời giữ lifecycle đã được operator cập nhật. Với OSPF, count, evidence và khoảng thời gian quan sát phản ánh snapshot mới nhất. Event đến muộn có thể khiến một số evidence chuyển sang incident khác. OSPF dùng `incident_id` từ correlation làm `aggregate_id`, severity mặc định `medium` và cooldown 300 giây. `window_start` và `window_end` biểu diễn khoảng bằng chứng, với biên cuối loại trừ. Các cột này giữ hình dạng `AlertRecord 1.0`.

### `alert_event_refs`

`event_id` là primary key, tham chiếu aggregate cùng `event_timestamp`. Bảng này chứng minh membership và liên kết điều tra tới Loki/raw spool mà không lưu raw lần thứ ba. Foreign key dùng `ON DELETE CASCADE`; API hiện không cung cấp delete.

### OSPF Phase 3

- `ospf_adjacencies` giữ identity và revision mới nhất. Conditional upsert tạo hoặc khóa hàng theo adjacency và bỏ qua revision cũ hoặc đã áp dụng.
- `ospf_incidents` giữ reporter state, thời điểm phục hồi kỹ thuật và thời điểm supersede. Trạng thái alert vận hành nằm trong `aggregated_alerts`.
- `ospf_incident_event_refs` giữ ID, thời gian, loại event và router ID của phía phát. Unique index chỉ cho một assignment hiện hành trên mỗi event trong một adjacency. Khi event đến muộn làm thay đổi membership, assignment cũ vẫn đọc được với `is_current=false`. Alert bị supersede còn truy cập được theo ID và được loại khỏi hàng đợi, thống kê và notification claim.
- `alert_status_history` ghi append-only khi tạo alert hoặc đổi status, gồm nguồn, actor, note và thời điểm. Migration tạo một hàng `baseline` từ trạng thái có sẵn, vì dữ liệu cũ không đủ để dựng lịch sử trước đó. Các call cùng status có thể cập nhật note mà vẫn giữ metadata của lần đổi trạng thái.

Một snapshot mới cập nhật revision, alert, trạng thái kỹ thuật, evidence và lịch sử trong cùng transaction PostgreSQL. Recovery đã xác nhận tự chuyển `new` hoặc `acknowledged` sang `resolved`, với nguồn `ospf_recovery`. ACK và note vẫn được giữ. Khi operator đã resolve, Full đến sau chỉ cập nhật thời điểm phục hồi kỹ thuật và evidence. Nếu event đến muộn làm mất xác nhận recovery, chỉ alert còn mang quyết định tự resolve mới trở lại status trước recovery, với nguồn `ospf_reassessment`. API ACK/status hiện có vẫn dùng được với session và CSRF.

Yêu cầu ACK khóa hàng alert bằng `FOR NO KEY UPDATE` rồi kiểm tra trạng thái trong
cùng transaction. Nếu Resolve đã commit, ACK trả lại bản ghi `resolved` hiện tại
và không ghi note, lịch sử hoặc outbox. Nếu ACK giữ khóa trước, Resolve chờ và
đóng alert sau khi ACK commit. Thao tác đổi status chủ ý sang `new` vẫn có thể mở lại alert.

`get_ospf_incident()` và `get_alert_history()` cung cấp evidence và lịch sử qua adapter. Queue mặc định của API và Grafana bao gồm cả alert đang mở hơn 24 giờ. Request API có `start` hoặc `end` tiếp tục áp dụng lọc thời gian tường minh. Danh sách thiết bị và thống kê theo khoảng thời gian giữ semantics hiện có.

## Migration và rollback

Migration chạy lúc FastAPI lifespan và processor khởi động khi `POSTGRES_DSN` được cấu hình. Startup dừng nếu migration mới lỗi hoặc checksum drift.

`003_ospf_lifecycle.sql` được áp dụng sau hai migration `001` và `002` hiện hữu. Khi quay lại bản ứng dụng cũ, giữ schema và volume đã migrate. Bản cũ không hiểu revision, supersession và nguồn thay đổi status của Phase 3.

Test PostgreSQL độc lập nằm ở `tests/integration/test_postgres_ospf_lifecycle.py`. Chạy với `NETWORKSEC_TEST_POSTGRES_DSN` trỏ tới database thử nghiệm có thể bỏ, và tài khoản được tạo schema. Mỗi test dùng một schema riêng. Test này chạy được với PostgreSQL riêng trên loopback.

## Resource budget

Compose giới hạn PostgreSQL 384 MiB, Loki 384 MiB, processor 256 MiB/0,75 CPU và Grafana 512 MiB. Cộng dashboard,
bot/generator tùy chọn và rsyslog, tổng hard memory limit của core stack vẫn phù hợp VM 5,3 GiB,
nhưng phải theo dõi RSS, disk growth, backlog và query latency. SQLite `synchronous=FULL` theo từng event
có thể là bottleneck trước CPU/RAM; chỉ tối ưu batch sau benchmark Ubuntu có bằng chứng.
