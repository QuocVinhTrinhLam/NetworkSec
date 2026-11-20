# Storage Phase 5

## Boundary và write path

```text
NormalizedEvent 1.0 ──> LokiLogStorage ──> Loki filesystem/TSDB
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

Upsert không hạ severity, không giảm count, không xóa lifecycle state đã acknowledge/resolve và không lùi `last_seen`.

### `alert_event_refs`

`event_id` là primary key, tham chiếu aggregate cùng `event_timestamp`. Bảng này chứng minh membership và liên kết điều tra tới Loki/raw spool mà không lưu raw lần thứ ba. Foreign key dùng `ON DELETE CASCADE`; API hiện không cung cấp delete.

## Migration và rollback

Migration chạy lúc FastAPI lifespan bắt đầu khi `POSTGRES_DSN` được cấu hình. Startup dừng nếu migration mới lỗi hoặc checksum drift; không tự xóa schema/database.

Migration `001` chỉ tiến (forward-only). Rollback Phase 5 là quay lại application version cũ nhưng giữ volume; không chạy drop table tự động. Trước migration phá vỡ tương thích ở phase sau phải backup và có script rollback/recovery riêng.

## Resource budget

Compose giới hạn PostgreSQL 384 MiB, Loki 384 MiB và processor 256 MiB/0,75 CPU. Cộng dashboard,
Grafana, bot/generator tùy chọn và rsyslog, tổng hard memory limit của core stack vẫn phù hợp VM 5,3 GiB,
nhưng phải theo dõi RSS, disk growth, backlog và query latency. SQLite `synchronous=FULL` theo từng event
có thể là bottleneck trước CPU/RAM; chỉ tối ưu batch sau benchmark Ubuntu có bằng chứng.
