# Correlation và Alert Aggregation

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

Luồng link-state dùng SQLite để aggregate và giữ event membership. Worker sau đó đưa bản ghi vào Loki và upsert aggregate sang PostgreSQL, nơi dashboard đọc và cập nhật trạng thái alert vận hành.

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

## OSPF Phase 2

Rule OSPF xử lý `DOWN` và `FULL` từ `NormalizedEvent 1.1`. Các trạng thái trung gian vẫn là telemetry trong Loki. Rule link-state tiếp tục dùng cửa sổ 60 giây. Một sự cố OSPF có thể kéo dài qua nhiều cửa sổ và vẫn giữ cùng `incident_id`.

### Định danh adjacency

Khóa gồm `scope` của collector, protocol OSPF, Area ID, cặp router ID đã sắp thứ tự và định danh link. Nối hai góc nhìn cần khai báo `links` với hai đầu interface trong `config/correlation_rules.yaml`. Mỗi đầu khớp chính xác `device_name`, `interface_name` và peer router ID. Area/local router ID mà event đã cung cấp phải khớp khai báo. Hai link song song dùng hai ID và hai cặp interface riêng.

Ví dụ dưới đây dành cho hai CHR chạy RouterOS v7. Thay tất cả placeholder trước khi
nạp cấu hình. `scope` và `id` là tên ổn định do operator đặt. `area` là Area ID OSPF
đã chốt cho lab.

```yaml
ospf:
  enabled: true
  scope: "<LAB_SCOPE>"
  max_clock_skew_seconds: 300
  links:
    - id: "<TRANSIT_LINK_ID>"
      area: 0.0.0.0
      endpoints:
        - router_id: "<R1_OSPF_ROUTER_ID>"
          device_name: "<R1_NORMALIZED_DEVICE_NAME>"
          interface_name: "<R1_OSPF_INTERFACE>"
        - router_id: "<R2_OSPF_ROUTER_ID>"
          device_name: "<R2_NORMALIZED_DEVICE_NAME>"
          interface_name: "<R2_OSPF_INTERFACE>"
```

Cấu hình trong repo để `links: []`. Thu thập các trường sau từ cả hai đầu trước khi bổ sung mapping.

- IPv4 Router ID local và peer từ adjacency/log OSPF. Local ID ở một đầu phải đúng
  bằng peer ID ở đầu kia. Xác nhận Area ID là `0.0.0.0` ở cả hai đầu.
- `device_name` chính xác sau parsing. Với RouterOS remote, parser ưu tiên hostname
  trong header. Worker dùng `source_host`, rồi `source_ip` làm fallback khi parser cần
  tên nguồn. Đối chiếu tên bằng event chuẩn hóa, kể cả chữ hoa/thường.
- `interface_name` đúng theo event. Với payload RouterOS được hỗ trợ, đó là tên nằm
  sau ký tự `%` trong khối `interface`. IPv4 trước `%` là địa chỉ interface local.

IP nguồn Syslog, subnet transit và IP interface giúp kiểm tra đường truyền.
Các trường này không nằm trong cấu trúc endpoint của `ospf.links`.

Khi chưa có mapping, event RouterOS đủ Area ID, local/peer ID và interface được theo
dõi riêng theo cặp `(device_name, interface_name)` của mỗi đầu. Hai link song song
có thể dùng cùng cặp router ID, nên chỉ ghép khi mapping khớp. Dạng log Cisco IOS
`ADJCHG` cần mapping để bổ sung Area ID và local Router ID. Thiếu định danh, khớp
nhiều link hoặc xung đột metadata khiến event chỉ đi vào Loki. Việc đổi scope,
link ID hoặc chuyển từ theo dõi riêng sang mapping tạo identity khác cho event mới.

### Thứ tự sự kiện và recovery

- SQLite ghi nhận mỗi `event_id` một lần trong mỗi `scope`. Các log Down khác ID vẫn là các quan sát khác nhau của cùng sự cố. Incident ID lấy từ adjacency và Down đáng tin cậy được ghi journal đầu tiên trong sự cố.
- Mỗi bên đã báo Down cần một Full cùng góc nhìn, có event time **lớn hơn** Down mới nhất của bên đó. Full từ bên chưa báo Down và Full lặp không thay thế bằng chứng còn thiếu. Một Down mới của bên đã báo Full trong khi phía kia vẫn pending sẽ buộc bên đó xác nhận lại.
- Khi timestamp bằng nhau, xử lý Down trước Full. Full cùng thời điểm không xác nhận recovery. Full đến trước Down theo thứ tự nhận vẫn có thể được dùng nếu event time thực sự mới hơn. Down hợp lệ sau khi sự cố đã hồi phục tạo incident mới.
- Ngưỡng lệch tuyệt đối giữa event time và `received_at` mặc định là 300 giây. Full vượt ngưỡng chỉ là evidence. Down vượt ngưỡng đến trong một outage đang mở được đặt theo thời điểm collector nhận, và bên đó cần Full đáng tin cậy muộn hơn thời điểm nhận cộng ngưỡng sai số. Down vượt ngưỡng đứng riêng được ghi nhận trong `unreliable_event_ids`. Giữ `received_at` gốc khi replay vì đó là một phần kiểm tra thứ tự.
- Event muộn có thể bổ sung một bên chưa được biết, làm một recovery tạm thời trở lại pending, hoặc thay đổi ranh giới giữa hai sự cố. Snapshot mới được dựng lại từ journal của đúng adjacency. Sau khi gộp, ID của Down hợp lệ được ghi đầu tiên được giữ, và ID bị gộp không còn trong snapshot mới.

### Lưu bền và điểm tích hợp Phase 3

`correlation.db` giữ journal append-only `ospf_observations`, gồm idempotency, adjacency, reporter và thời gian dùng để quyết định. `CorrelationResult.ospf` chứa projection kỹ thuật với `adjacency_id`, `revision`, incidents và event IDs. `list_ospf_adjacencies()` và `ospf_snapshot()` cho phép dựng lại projection sau restart mà không cần phát lại syslog. Việc dựng lại hiện đọc lịch sử riêng của adjacency, phù hợp với quy mô lab. Cần đo chi phí trước khi dùng cho lịch sử lớn.

Khi Loki ghi lỗi sau khi SQLite commit, worker retry cùng offset. Correlation trả snapshot hiện tại cho event trùng. PostgreSQL sở hữu trạng thái vận hành gồm status, ACK, actor và note. [Storage Phase 3](storage.md#ospf-phase-3) mô tả cách worker ghi snapshot sau Loki và cập nhật checkpoint.

Chốt mapping trước khi xử lý log live để các observation tiếp theo đi vào cùng adjacency đã ghi. Thay đổi `scope` hoặc ID link tạo identity mới, nên cần đối soát dữ liệu cũ khi đổi mapping.
