# Processing Worker

## Mục tiêu và data flow

`processor` là consumer liên tục duy nhất nối ingestion với storage nghiệp vụ:

```text
TCP/UDP :5514
      |
   rsyslog
      |-- raw.log (bằng chứng `$rawmsg`, bất biến)
      `-- processor.jsonl (envelope 1.0, disk-assisted queue)
                     |
              byte checkpoint
                     |
       parse -> normalize -> correlate
          | malformed/unknown   | parsed
          v                     v
       SQLite DLQ         Loki event -> PostgreSQL aggregate/ref
```

Processor tái sử dụng `parse_syslog`, `CorrelationEngine`, `LokiLogStorage`,
`PostgresAlertStorage` và `StorageWriter`; không có parser/rule/storage implementation thứ hai.

## Envelope 1.0

Mỗi dòng `processor.jsonl` là JSON object có đúng các field:

- `schema_version: "1.0"`;
- `received_at`: RFC 3339 có timezone;
- `source_host`, `source_ip`: metadata do rsyslog cung cấp, có thể null;
- `raw_message`: `$rawmsg` đầy đủ để bảo toàn evidence;
- `parse_message`: payload sau standard Syslog PRI (`rawmsg-after-pri`) dùng cho parser;

rsyslog dùng JSON escaping chuẩn và `addLF="on"`. Worker chỉ đọc record có newline hoàn chỉnh; partial
write không được parse hoặc checkpoint. Envelope tối đa 128 KiB để chống record lỗi gây tăng RAM vô hạn.

## Checkpoint và idempotency

`processor-state.db` lưu identity file `(device, inode)` và byte offset. Parsed event đi qua các bước dưới đây.

1. Loki nhận normalized event. Processor lưu xác nhận ghi Loki cho event đang xử lý.
2. Correlation SQLite ghi membership link-state hoặc journal OSPF theo `event_id`.
3. PostgreSQL cập nhật projection link-state hoặc OSPF trong cùng transaction với catalog.
4. Processor ghi receipt `event_id` cùng inode/byte range và cập nhật checkpoint trong một transaction.

Các lỗi cần retry ở bước 1–3 giữ nguyên checkpoint. Retry có thể tạo physical delivery lặp ở Loki, nhưng
`event_id` làm correlation và PostgreSQL idempotent; Loki query adapter cũng loại trùng theo `event_id`.
Đây là at-least-once delivery với exactly-once logic, không phải distributed transaction.

Restart đọc lại offset từ volume `processor-state`. Nếu đã lưu xác nhận Loki, lần retry tiếp tục
từ correlation với cùng `event_id`. Conditional upsert chặn PostgreSQL áp dụng cùng revision OSPF
lần nữa. Khi lỗi PostgreSQL xảy ra sau khi Loki đã ghi, receipt hoàn tất và offset vẫn chưa tiến.

Lần đầu spool rảnh sau khi khởi động, worker đối soát các adjacency đã journal trong Phase 2. Chỉ snapshot có đủ receipt cho evidence mới được áp dụng. Đường xử lý trực tiếp cũng yêu cầu receipt cho bằng chứng cũ, với event hiện tại được ghi Loki trước PostgreSQL. Nếu thiếu receipt, xử lý báo blocked để tránh publish evidence chưa đi qua pipeline. Giữ `processor-state.db` và `correlation.db` nhất quán khi restore.

Compose chạy một processor active trên một spool. Nếu restore journal về revision cũ hơn PostgreSQL, đối soát bằng backup thống nhất và replay bản gốc để giữ thứ tự revision và incident ID.

## Dead-letter strategy

JSON/UTF-8/schema không hợp lệ, parser `malformed`, và format `unknown` được coi là poison record. Worker
ghi cùng transaction SQLite:

- reason code không chứa raw payload;
- source path, file identity, start/end byte offset;
- SHA-256 và bản ghi envelope gốc;
- checkpoint kế tiếp.

Vì vậy poison record không chặn pipeline và vẫn truy ngược được tới `raw.log`. Với record hỏng lớn hơn
128 KiB, DLQ chỉ giữ prefix bị giới hạn cùng byte range; spool gốc vẫn là nguồn sự thật.
Sự kiện bị Loki từ chối với `too_far_behind` đi vào DLQ với reason
`loki_entry_too_far_behind` trước bước correlation. Các lỗi lưu trữ còn lại và lỗi correlation giữ
checkpoint để retry.

DLQ có thể chứa dữ liệu nhạy cảm từ thiết bị. Không in nội dung qua log, không commit database, chỉ cho
service account/nhóm vận hành đọc volume. Chưa có auto-delete hoặc auto-replay DLQ; remediation phải review
parser/fixture rồi replay raw evidence có chủ đích.

## Health và vận hành

Health state gồm `starting`, `healthy`, `blocked`, heartbeat, processed/dead-letter counters. Idle worker
vẫn cập nhật heartbeat. Downstream exception đặt `blocked`; record hiện tại được retry sau
`PROCESSOR_RETRY_INTERVAL_SECONDS`. Container health check yêu cầu `healthy` và heartbeat mới hơn
`PROCESSOR_HEALTH_MAX_AGE_SECONDS`.

Các volume cần backup nhất quán:

- `syslog-raw`: raw evidence và processing envelope;
- `processor-state`: checkpoint, DLQ, correlation trace;
- `postgres-data`: alert lifecycle/notification state;
- `loki-data`: searchable normalized events.

Không dùng `docker compose down -v`, không sửa SQLite trực tiếp và không rotate/truncate spool khi worker
đang chạy. Rotation cần một thiết kế handoff inode riêng trước khi bật.

## Acceptance tests

Unit/component tests chạy không cần Docker và cover 100-event aggregation, replay, restart, storage failure,
partial record, DLQ và Telegram cooldown claim. Test worker OSPF mô phỏng Loki lỗi trước khi PostgreSQL ghi, PostgreSQL lỗi sau khi Loki ghi, retry cùng offset và import journal đã checkpoint. [Test PostgreSQL độc lập](storage.md#migration-và-rollback) kiểm tra migration, rollback, concurrent snapshot, stale/repeated Full và việc giữ quyết định operator. Test stack Compose là opt-in:

```bash
docker compose up -d --build --wait
RUN_PROCESSOR_INTEGRATION=1 python -m pytest -m processor_integration tests/integration
```

Không được coi test live là PASS nếu Docker services hoặc marker này chưa thực sự chạy.
