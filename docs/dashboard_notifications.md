# Dashboard, Grafana và Telegram — Phase 6

## Custom Dashboard

Dashboard server-rendered hiện hữu được giữ nguyên layout, session, CSRF, HTMX refresh và Chart.js. `DASHBOARD_BACKEND` điều khiển nguồn dữ liệu:

- `legacy` (mặc định ngoài Compose): SQLite và UI cũ;
- `operational`: PostgreSQL cho aggregate alert, Loki cho normalized event.

Compose đặt `operational`. Không tự fallback sang SQLite khi Loki/PostgreSQL lỗi vì fallback có thể hiển thị dữ liệu cũ như dữ liệu hiện hành; UI trả `503` rõ ràng.

Các view operational:

- `/dashboard`: metrics/severity/timeline, recent aggregate alerts và recent normalized events;
- `/alerts`: device, severity, event type, status và time-range filters; hiển thị `count`, `first_seen`, `last_seen`, severity và lifecycle status;
- `/alerts/{aggregate_id}`: aggregate detail và acknowledgement bằng CSRF-protected form;
- `/events`: Loki event stream với device, severity, event type, vendor và time filters.

Raw message không được render trên event-list page. Điều tra raw dùng Loki/Grafana hoặc API đã xác thực để giảm nguy cơ log injection và làm nhẹ HTML.

## Grafana

Grafana được provision hoàn toàn từ repository:

- data source UID `network-events-loki`, proxy URL `http://loki:3100`, read-only trong UI;
- file dashboard provider kiểm tra thay đổi mỗi 30 giây;
- dashboard `Network Event Operations` có total event, event rate theo severity và normalized log stream;
- variables: severity, event type và device regex.

Grafana chỉ bind loopback mặc định. Anonymous access và user self-signup bị tắt. `GRAFANA_ADMIN_PASSWORD` phải được đặt trong `.env`; không dùng credential mặc định khi deploy.

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

## Migration

`002_notification_delivery.sql` thêm `last_notification_event_count` và bảng `telegram_message_state`. Migration forward-only, checksum-protected và không xóa message state/alert data khi rollback application.
