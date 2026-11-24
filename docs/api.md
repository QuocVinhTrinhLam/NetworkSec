# Legacy event and incident API v1

Base path: `/api/v1`. Contract version in paginated responses: `1.0`.

## Authentication and errors

API dùng bearer token và kiểm tra quyền theo vai trò. Request chưa xác thực nhận `401`.
Tài khoản thiếu quyền nhận `403`. [API vận hành đầy đủ](api-contract.md).

Validation path/query/body do FastAPI/Pydantic thực hiện và trả `422`. Các lỗi backend được chuẩn hóa:

| HTTP | Ý nghĩa |
|---|---|
| 400 | Cursor event không hợp lệ |
| 401 | Chưa đăng nhập |
| 403 | Thiếu quyền |
| 404 | Alert không tồn tại |
| 422 | Enum, ID, pagination, payload hoặc time range sai |
| 502 | Backend trả dữ liệu/lệnh không hợp lệ |
| 503 | Loki hoặc PostgreSQL không truy cập được |

Không trả DSN, SQL, response body nội bộ của Loki hoặc credential trong lỗi API.

## Time range và pagination

`start` và `end` là ISO 8601 có timezone. Mặc định là 24 giờ gần nhất. `start` phải nhỏ hơn `end`; mọi giá trị được chuẩn hóa UTC.

- Event dùng `page_size` 1–500 và opaque `cursor`. Client không phân tích hoặc tự tạo cursor.
- Alert dùng `page` 1–1.000 và `page_size` 1–200. Response có `total`.
- Loki đọc khoảng `[start, end)` với `direction=backward`. API sắp xếp giảm dần theo
  timestamp nanosecond và `event_id` trong từng nhóm cùng timestamp. Cursor mới giữ
  vị trí theo hai giá trị này. Cursor cũ có danh sách ID tại biên vẫn đọc được.
- Giữ nguyên mốc thời gian và bộ lọc khi chuyển trang. Cursor nằm ngoài khoảng thời
  gian được yêu cầu trả HTTP 400. API đọc dữ liệu Loki hiện tại ở mỗi trang.

## Endpoints

### `GET /api/v1/events`

Query normalized events từ Loki.

Filters: `start`, `end`, `severity`, `event_type`, `vendor`, `device_name`, `interface_name`, `page_size`, `cursor`, `include_ospf`.

Danh sách trả `raw_message="[restricted]"` và giữ nguyên `event_id`. Admin có thể yêu cầu bằng
chứng đã che thông tin nhạy cảm bằng `include_raw=true` trên endpoint chi tiết.
[Hợp đồng API vận hành](api-contract.md)

`severity`, `event_type`, `vendor` là Loki labels cardinality thấp. `device_name` và `interface_name` lọc sau `| json`, không tạo label cardinality cao. Response:

```json
{
  "schema_version": "1.0",
  "items": ["NormalizedEvent 1.0 objects"],
  "page_size": 100,
  "next_cursor": "opaque-or-null"
}
```

Nếu raw spool replay cùng `event_id` tại timestamp gốc, adapter loại bản lặp và ưu tiên
`received_at` sớm nhất. Khi một lần đọc đạt giới hạn dòng Loki, adapter đọc thêm
trước khi kết luận hết kết quả hoặc phát cursor ở nhóm cùng timestamp. Adapter dùng
tối đa 5.000 dòng mỗi lần đọc và 24 lần đọc mỗi trang. Nếu không thể đọc đủ nhóm
timestamp trong các giới hạn này, API trả HTTP 502 để client nhận biết trang chưa
thể hoàn tất.

Request mặc định chỉ đọc stream `schema_version="1.0"` trước khi phân trang. Client muốn đọc OSPF gửi `include_ospf=true`. Các item khi đó có thể là event `1.0` hoặc `1.1` và client kiểm tra `items[].schema_version`. Page envelope vẫn là `1.0`. Ví dụ `GET /api/v1/events?include_ospf=true&event_type=routing_neighbor_up`. Khi dùng cursor, giữ nguyên các filter, gồm `include_ospf`. Xem [schema OSPF và quy trình nâng phiên bản](parsing.md#ospfv2-phase-1).

Phần này mô tả chế độ `view=legacy`. Client mới dùng `/api/v1/events/catalog` cho phân trang theo
số và bộ lọc registry. Truy cập raw log qua bearer yêu cầu role Admin và
`include_raw=true` ở endpoint chi tiết. [API vận hành](api-contract.md#events-incidents-and-topology).

### `GET /api/v1/alerts`

Query aggregate state từ PostgreSQL.

Filters: `start`, `end`, `severity`, `status`, `event_type`, `device_name`, `interface_name`, `rule_id`, `source_ip`, `search`, `page`, `page_size`.

`status` nhận `new`, `acknowledged`, `resolved`. Khi truyền `start` hoặc `end`, API chọn alert có khoảng quan sát giao với range (`last_seen >= start` và `first_seen <= end`). Khi bỏ cả hai, queue giữ cả alert `new` và `acknowledged` đã mở hơn 24 giờ. Alert `resolved` vẫn áp dụng khoảng mặc định. Incident OSPF bị supersede vẫn có thể tra cứu trực tiếp bằng ID.

`rule_id` khớp chính xác. `device_name` có thể khớp tên thiết bị hoặc một router ID trong adjacency OSPF. `source_ip` khớp địa chỉ IPv4/IPv6 trong evidence có metadata đó. Router ID OSPF và địa chỉ nguồn syslog không được dùng để suy ra `source_ip`. `search` tìm chuỗi literal không phân biệt hoa thường trong metadata alert, loại event, operator note và IP nguồn đã lưu. Để tìm nội dung log, dùng Loki/Grafana.

### `GET /api/v1/alerts/{aggregate_id}`

Trả một `AlertRecord 1.0`. `aggregate_id` phải là đúng 64 ký tự hex lowercase.

### `GET /api/v1/alerts/{aggregate_id}/evidence`

Yêu cầu session hiện có. Trả `AlertEvidenceResponse 1.0` gồm `alert_id`, `event_refs`, `history` và `ospf`. Mỗi reference có ID, timestamp, loại event nếu biết, reporter hoặc IP nguồn nếu có, và cờ `is_current`. `history` ghi status trước/sau, nguồn thay đổi, actor, note và thời điểm. `ospf` chứa identity, area, reporter state, thời điểm recovery kỹ thuật và supersession. Alert thường có `ospf=null`. Endpoint trả `404` nếu alert chưa tồn tại.

Các response `AlertRecord` và `EventPageResponse` hiện hữu giữ nguyên shape. Bằng chứng raw vẫn lưu trong Loki, UI có link tới `/events?event_id=…&event_at=…` để mở đúng record.

### `POST /api/v1/alerts/{aggregate_id}/acknowledge`

Body tùy chọn:

```json
{"note": "Đang kiểm tra interface vật lý"}
```

ACK chuyển alert `new` sang `acknowledged` và ghi actor từ session, thời điểm, note và lịch sử.
ACK lặp khi alert còn `acknowledged` có thể cập nhật note đã cung cấp và giữ actor,
thời điểm và lịch sử ACK đầu tiên. Nếu alert đã `resolved`, API trả HTTP 200 với
`AlertRecord` hiện tại. ACK lúc đó giữ nguyên trạng thái, note và lịch sử. Alert chưa
tồn tại vẫn trả HTTP 404.

### `PATCH /api/v1/alerts/{aggregate_id}/status`

```json
{"status": "resolved", "note": "Link ổn định sau thay cáp"}
```

Cho phép `new`, `acknowledged`, `resolved`. Status `acknowledged` áp dụng cùng điều kiện
và kết quả như endpoint ACK. Status `resolved` đóng alert. Mở lại alert bằng `new` yêu cầu
role Admin. Gửi lại cùng trạng thái giữ nguyên lịch sử chuyển trạng thái.

### `GET /api/v1/storage/health`

Kiểm tra readiness Loki và PostgreSQL, trả `ok` khi cả hai sẵn sàng, nếu không trả `degraded`. Endpoint vẫn trả HTTP 200 để dashboard có thể hiển thị từng backend; healthcheck container chính vẫn dùng `/health`.

## OpenAPI

FastAPI sinh OpenAPI tại `/openapi.json` trong môi trường phát triển. Cấu hình production
tắt OpenAPI và giao diện tài liệu tương tác.
