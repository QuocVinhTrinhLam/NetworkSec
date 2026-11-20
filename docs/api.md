# Backend API v1

Base path: `/api/v1`. Contract version in paginated responses: `1.0`.

## Authentication and errors

API dùng cùng session cookie với Custom Dashboard. Request chưa đăng nhập nhận `401` và `WWW-Authenticate: Session`. Các mutation còn yêu cầu header `X-CSRF-Token` lấy từ session/dashboard; thiếu hoặc sai token nhận `403`.

Validation path/query/body do FastAPI/Pydantic thực hiện và trả `422`. Các lỗi backend được chuẩn hóa:

| HTTP | Ý nghĩa |
|---|---|
| 400 | Cursor event không hợp lệ |
| 401 | Chưa đăng nhập |
| 403 | CSRF token thiếu/sai |
| 404 | Alert không tồn tại |
| 422 | Enum, ID, pagination, payload hoặc time range sai |
| 502 | Backend trả dữ liệu/lệnh không hợp lệ |
| 503 | Loki hoặc PostgreSQL không truy cập được |

Không trả DSN, SQL, response body nội bộ của Loki hoặc credential trong lỗi API.

## Time range và pagination

`start` và `end` là ISO 8601 có timezone. Mặc định là 24 giờ gần nhất. `start` phải nhỏ hơn `end`; mọi giá trị được chuẩn hóa UTC.

- Event dùng `page_size` 1–500 và opaque `cursor`. Client không phân tích hoặc tự tạo cursor.
- Alert dùng `page` từ 1 và `page_size` 1–200; response có `total`.
- Loki query chạy `direction=backward`. Cursor giữ timestamp nanosecond và event ID đã thấy tại đúng biên timestamp để không bỏ sót event có cùng timestamp.

## Endpoints

### `GET /api/v1/events`

Query normalized events từ Loki.

Filters: `start`, `end`, `severity`, `event_type`, `vendor`, `device_name`, `interface_name`, `page_size`, `cursor`.

`severity`, `event_type`, `vendor` là Loki labels cardinality thấp. `device_name` và `interface_name` lọc sau `| json`, không tạo label cardinality cao. Response:

```json
{
  "schema_version": "1.0",
  "items": ["NormalizedEvent 1.0 objects"],
  "page_size": 100,
  "next_cursor": "opaque-or-null"
}
```

Nếu raw spool replay cùng `event_id`, adapter loại bản lặp trong kết quả API.

### `GET /api/v1/alerts`

Query aggregate state từ PostgreSQL.

Filters: `start`, `end`, `severity`, `status`, `event_type`, `device_name`, `interface_name`, `page`, `page_size`.

`status` nhận `new`, `acknowledged`, `resolved`. Time range chọn alert có khoảng quan sát giao với range (`last_seen >= start` và `first_seen <= end`).

### `GET /api/v1/alerts/{aggregate_id}`

Trả một `AlertRecord 1.0`. `aggregate_id` phải là đúng 64 ký tự hex lowercase.

### `POST /api/v1/alerts/{aggregate_id}/acknowledge`

Body tùy chọn:

```json
{"note": "Đang kiểm tra interface vật lý"}
```

Chuyển status sang `acknowledged`, ghi `acknowledged_by`, `acknowledged_at`, status audit và note. Actor lấy từ session, không nhận từ body.

### `PATCH /api/v1/alerts/{aggregate_id}/status`

```json
{"status": "resolved", "note": "Link ổn định sau thay cáp"}
```

Cho phép `new`, `acknowledged`, `resolved`. Status `acknowledged` dùng cùng semantics với endpoint acknowledge.

### `GET /api/v1/storage/health`

Kiểm tra readiness Loki và PostgreSQL, trả `ok` khi cả hai sẵn sàng, nếu không trả `degraded`. Endpoint vẫn trả HTTP 200 để dashboard có thể hiển thị từng backend; healthcheck container chính vẫn dùng `/health`.

## OpenAPI

FastAPI sinh OpenAPI tại `/openapi.json`. Swagger/ReDoc mặc định của framework có thể dùng trong môi trường phát triển đã đăng nhập, nhưng không nên expose public nếu chưa có reverse proxy, TLS và access policy.
