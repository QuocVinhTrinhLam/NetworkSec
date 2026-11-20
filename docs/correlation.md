# Correlation và Alert Aggregation — Phase 4

## Data flow

```text
NormalizedEvent 1.0
        |
        v
match correlation rule (YAML)
        |
        v
derive UTC event-time window + group key
        |
        v
BEGIN IMMEDIATE (SQLite)
  ├─ reject replayed event_id
  ├─ insert/update one aggregate
  └─ persist raw + normalized event membership
COMMIT
        |
        +--> trace_events(aggregate_id)
        |
        +--> atomic notification cooldown claim --> Telegram worker
```

Phase 4 dùng SQLite hiện hữu để giữ footprint nhỏ trên VM 2 vCPU/5,3 GiB RAM. Không thêm Kafka, Redis hoặc PostgreSQL. PostgreSQL/outbox chỉ nên được xem xét ở phase sau nếu đo tải hoặc yêu cầu delivery chứng minh SQLite không đủ.

## Rule và khóa nhóm

Rule được validate theo contract `schema_version: "1.0"` trong `config/correlation_rules.yaml`. Không có biểu thức tùy ý hay code động; chỉ các field trong allowlist được dùng làm khóa.

Rule mặc định `interface-link-state`:

- nhận `link_up` và `link_down`;
- yêu cầu `device_name` và `interface_name`;
- nhóm theo `(device_name, interface_name, event_family=link_state, UTC window)`;
- dùng cửa sổ 60 giây và cooldown notification 300 giây.

`link_up` và `link_down` cố ý thuộc cùng họ `link_state`. Nếu đưa `event_type` gốc vào group key thì bài test flap sẽ tạo hai alert, trái với yêu cầu một alert cho chuỗi lên/xuống liên quan. Aggregate vẫn giữ tập `event_types`, và từng trace vẫn giữ chính xác loại sự kiện gốc.

Có thể cấu hình `event_type` thay cho `event_family` trong `group_by` khi hai loại phải tách riêng. Thay đổi rule ID hoặc group key tạo identity aggregate mới; không sửa rule giữa một lần replay nếu muốn kết quả giữ nguyên.

## Semantics cửa sổ

Cửa sổ là tumbling window theo event time UTC:

```text
window_start = floor(event_timestamp / window_seconds) * window_seconds
window_end   = window_start + window_seconds
membership  = [window_start, window_end)
```

Biên cuối không thuộc cửa sổ. Ví dụ với 60 giây: `12:00:59.999` thuộc cửa sổ 12:00, còn `12:01:00.000` mở aggregate mới. Cách này khiến kết quả độc lập với thứ tự nhận và ổn định qua restart/replay. Đổi lại, một flap kéo dài qua đúng biên phút sẽ tạo hai aggregate; dashboard có thể hiển thị liền nhau nhưng engine không merge hai cửa sổ.

## Dedup, aggregation và traceability

- `NormalizedEvent.event_id` là khóa idempotency duy nhất trong `correlation_events`.
- Ghi raw trace và tăng aggregate diễn ra trong cùng transaction `BEGIN IMMEDIATE`.
- Replay cùng `event_id` trả về `duplicate=true`, không tăng `count` và không tạo trace thứ hai.
- `count` là số event ID duy nhất trong aggregate.
- `first_seen`/`last_seen` là min/max event timestamp, nên event out-of-order vẫn đúng.
- `severity` là severity lớn nhất theo thứ tự `low < medium < high < critical`.
- `event_types` là tập loại gốc đã quan sát, sắp xếp ổn định khi lưu.
- Mỗi trace giữ `raw_message` bất biến và toàn bộ `NormalizedEvent 1.0`; tra cứu bằng `aggregate_id`.

Raw spool của rsyslog vẫn là bằng chứng gốc dài hạn. Bản raw trong SQLite là tham chiếu điều tra gắn với aggregate, không thay thế retention/rotation của spool.

## Notification cooldown

`claim_notification(aggregate_id, now)` thực hiện read/check/update trong một write transaction. Claim đầu tiên được phép; các claim trước `last_notification_at + cooldown` bị từ chối. State này nằm trong SQLite nên vẫn có hiệu lực sau restart và ngăn nhiều worker tạo quyết định Telegram trùng.

Đây là cơ chế claim trước khi gửi (at-most-once trong thời gian cooldown). Nếu process dừng sau claim nhưng trước khi Telegram xác nhận, notification có thể bị hoãn tới hết cooldown. Transactional outbox/delivery receipt là nâng cấp Phase 5 khi cần at-least-once mà vẫn tránh duplicate ở mức nghiệp vụ.

## Failure và recovery

- Crash trước commit: cả raw trace và count đều rollback.
- Crash sau commit: replay cùng `event_id` được nhận diện là duplicate.
- Restart: mở lại cùng database và rule config; aggregate, trace và cooldown tiếp tục từ state đã commit.
- Event không match rule hoặc thiếu required field không được ghi vào correlation state; raw spool vẫn giữ payload để sửa config/parser rồi replay.
- SQLite dùng WAL, foreign key và busy timeout; transaction ngắn để phù hợp một processor ở quy mô lab.

Không xóa database để recovery. Sao lưu file database cùng WAL/SHM bằng snapshot nhất quán hoặc dừng writer ngắn; sau restore, replay raw spool là an toàn nhờ `event_id`.

## Acceptance test

Test tạo 100 `NormalizedEvent` Link Up/Down duy nhất của cùng `core-sw-01/GigabitEthernet0/1`, timestamp từ `12:00:00.000` tới `12:00:49.500` trong một cửa sổ 60 giây. Kỳ vọng:

- đúng một aggregate;
- `count = 100`;
- đủ 100 trace với raw message và event ID gốc;
- severity là mức lớn nhất;
- claim Telegram đầu tiên được phép, claim kế tiếp trong cooldown bị chặn.

Các test riêng kiểm tra biên `[start, end)`, duplicate delivery, out-of-order, phân tách device/interface và restart với cooldown persisted.
