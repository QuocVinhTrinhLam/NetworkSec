# Dashboard, Grafana và Telegram

## Custom Dashboard

Custom Dashboard dùng FastAPI, Jinja2, session, CSRF và HTMX hiện có. `DASHBOARD_BACKEND` điều khiển nguồn dữ liệu:

- `legacy` (mặc định ngoài Compose): SQLite và giao diện demo có Chart.js;
- `operational`: PostgreSQL cho aggregate alert, Loki cho normalized event.

Compose đặt `operational`. Trang incident và hàng đợi đọc PostgreSQL, nên vẫn tải được khi Loki không khả dụng. Link mở raw evidence cần Loki. Các view trả `503` nếu backend mà view cần đang lỗi.

Các view operational:

- `/dashboard` hiển thị New, Acknowledged, alert High/Critical đang mở, alert resolve trong 24 giờ và recent alert queue. Biểu đồ và truy vấn telemetry dùng Grafana.
- `/alerts` lọc theo khoảng thời gian, loại event, severity, thiết bị/router ID, rule ID, source IP, status và search metadata. Hàng đợi hiển thị neighbor nếu có, first/last seen, status và ACK. Pagination giữ tất cả filter.
- `/alerts/{aggregate_id}` hiển thị OSPF area, cặp router ID, trạng thái recovery kỹ thuật, lịch sử vận hành và evidence. Form ACK/Resolve yêu cầu session và CSRF, nhận note tùy chọn. Kết quả resolve thủ công và recovery kỹ thuật được hiển thị riêng.
- `/alerts/export.csv` xuất PostgreSQL với cùng filter và bỏ giới hạn trang đang xem. Export lấy tối đa 5.000 alert, có header `X-Export-Truncated: true` khi vượt giới hạn và áp dụng chống spreadsheet formula. Demo giữ CSV từ SQLite.
- `/events` hỗ trợ xem stream và mở log bằng ID/timestamp từ incident. Trang stream hiển thị metadata. Chế độ xem từng evidence hiển thị raw log đã escape.

Migration `004_alert_evidence_filters.sql` bổ sung source IP và event type cho reference thường. Bản ghi lịch sử thiếu metadata vẫn có thể mở từ incident, nhưng lọc IP chỉ khớp khi evidence có địa chỉ đã lưu. Phát lại event có thể điền metadata thiếu trên reference hiện có. Log OSPF Phase 1 thường có router ID và không có `source_ip`, nên dùng router ID hoặc link để tìm những incident đó. [API evidence](api.md#get-apiv1alertsaggregate_idevidence)

## Grafana

Grafana được provision hoàn toàn từ repository:

- data source UID `network-events-loki`, proxy URL `http://loki:3100`, read-only trong UI;
- file dashboard provider kiểm tra thay đổi mỗi 30 giây;
- dashboard `Network Event Operations` có total event, event rate theo severity và normalized log stream;
- variables: severity, event type và device regex.

Grafana chỉ bind loopback mặc định. Anonymous access và user self-signup bị tắt. `GRAFANA_ADMIN_PASSWORD` phải được đặt trong `.env`; không dùng credential mặc định khi deploy.

### OSPF Observability

Dashboard `OSPF Observability` dùng cùng Loki datasource. Các panel hiển thị số bản ghi Down và Full, timeline Down/Full/intermediate, severity, 15 tổ hợp vendor/thiết bị thường gặp và log stream. Chúng đếm **quan sát syslog**. Hai đầu router có thể sinh hai bản ghi cho cùng sự cố. Custom Dashboard giữ incident ID, ACK và recovery đã được correlation xác nhận.

Dashboard truy vấn cả record 1.0 lẫn 1.1 bằng các label có sẵn `job`, `event_type`, `vendor` và `severity`. Thiết bị được trích từ JSON tại thời điểm truy vấn. Router ID, `event_id` và `aggregate_id` không được thêm vào label Loki.

Trong Grafana Explore, chọn thời gian hẹp quanh sự cố rồi lọc theo thiết bị hoặc router.

```logql
{job="network-events",event_type=~"routing_neighbor_(down|up|state_change)"}
| json device_name="device_name", ospf_area="ospf_area", neighbor_router_id="neighbor_router_id"
| device_name="R1" | ospf_area="0.0.0.0" | neighbor_router_id="192.0.2.2"
```

Nếu log thiếu area, bỏ điều kiện area. Khi cần kiểm tra đúng evidence, lấy ID từ trang incident và lọc JSON với `| json event_id="event_id" | event_id="<event_id>"` trong khoảng thời gian của bản ghi.

## Telegram aggregate delivery

Bot dùng `AggregatedNotificationWorker` khi `POSTGRES_DSN` tồn tại; nếu không, legacy SQLite worker vẫn hoạt động.

PostgreSQL claim semantics:

1. Chỉ alert không `resolved`, đạt `TELEGRAM_MIN_SEVERITY`, có `event_count` mới và đã hết cooldown mới eligible.
2. `FOR UPDATE SKIP LOCKED` khóa batch để hai worker không claim cùng aggregate.
3. Claim atomically cập nhật `last_notification_at`, `last_notification_event_count` và `notification_count`.
4. `telegram_message_state(aggregate_id, chat_id)` giữ Telegram `message_id`.
5. Lần đầu dùng `sendMessage`; lần sau sau cooldown dùng `editMessageText`, không tạo message trùng.

Threshold hỗ trợ `low`, `medium`, `high`, `critical`. Cooldown lấy từ correlation rule đã persist trong aggregate.

Giới hạn last-mile: Telegram không có idempotency key cho `sendMessage`. Nếu process chết đúng sau Telegram chấp nhận message đầu tiên nhưng trước khi PostgreSQL lưu `message_id`, lần phục hồi không thể chứng minh delivery đó. Atomic claim ưu tiên không gửi lại cho tới khi aggregate có event count mới, giảm duplicate nhưng có thể trì hoãn notification. Không log token/chat payload và không gửi notification thật trong test.

### Telegram OSPF

OSPF dùng hàng đợi riêng để xử lý cả incident đang mở lẫn đã đóng. PostgreSQL ghi Down khi incident được tạo và ghi Recovery khi trạng thái kỹ thuật chuyển sang đã xác nhận. ACK, resolve/reopen của operator, recovery bị rút lại và supersession cập nhật tin hiện có. Resolve thủ công giữ ý nghĩa vận hành và vẫn có thể được theo sau bởi Recovery kỹ thuật. Recovery đang chờ bị log đến muộn phủ định được đánh dấu và bỏ qua.

- Down áp dụng `TELEGRAM_MIN_SEVERITY` để tạo một tin cho mỗi incident và chat. Bot tái sử dụng message ID khi nâng cấp. Bản ghi Down từ cả hai router và event replay dùng cùng incident. Nhánh link-state tiếp tục sử dụng threshold, cooldown và cập nhật count hiện có.
- Khóa chuyển trạng thái gồm incident và identity của lần mở, revision correlation hoặc thay đổi operator. Mỗi chat có receipt riêng. Worker sửa cùng message ID cho các chuyển trạng thái đã ghi. Recovery và các correction được xử lý ngay khi đến lượt, kể cả trong cooldown của link-state.
- Lần gửi đầu chỉ được xếp lại khi Telegram trả rate limit rõ ràng. Nếu kết quả gửi không chắc chắn hoặc worker dừng trước khi lưu message ID, receipt bảo vệ khỏi gửi thêm một tin. Hệ quả là có thể thiếu tin cho chat đó. Sửa tin có thể thử lại trên cùng message ID và transition. Claim sửa tin dang dở được phục hồi sau lease 10 phút.
- Compose truyền `APP_URL` cho bot. Đặt URL dashboard HTTP(S) mà người nhận truy cập được. URL loopback, URL có credential và URL sai định dạng được lược khỏi OSPF keyboard. Nội dung gửi gồm severity, cặp router, area, scope, link, thời điểm và incident ID. Nội dung ghi chú operator ở lại Custom Dashboard.

## Migration

`002_notification_delivery.sql` thêm `last_notification_event_count` và bảng `telegram_message_state`. Migration forward-only, checksum-protected và không xóa message state/alert data khi rollback application.

`005_ospf_notification_delivery.sql` bổ sung outbox và receipt OSPF. Trigger ghi chuyển trạng thái trong cùng transaction với incident và lịch sử operator. Migration giữ message ID và chỉ khởi tạo thông báo Down cho incident hiện đang mở. Nếu luồng cũ đã claim incident mà chat chưa có message ID, worker mới bỏ qua lần gửi đầu vì kết quả gửi cũ chưa xác minh được.

Kiểm tra cấu hình dashboard và gateway mock bằng `tests/test_ospf_observability.py` và `tests/test_ospf_notifications.py`. `tests/integration/test_ospf_loki_queries.py` cần `NETWORKSEC_TEST_LOKI_URL` trỏ tới Loki thử nghiệm. `tests/integration/test_postgres_ospf_lifecycle.py` cần `NETWORKSEC_TEST_POSTGRES_DSN` trỏ tới PostgreSQL thử nghiệm và vẫn dùng gateway Telegram giả lập.
