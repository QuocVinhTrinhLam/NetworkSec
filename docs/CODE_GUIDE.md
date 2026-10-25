# Hướng dẫn đọc và giải thích code

## 1. Luồng dữ liệu

`WazuhClient` chỉ làm HTTP và trả document thô. `normalize_alert` chuyển mọi vendor về `Alert`. `Database.insert_alert` lưu alert và tạo một outbox bằng cột `notification_processed=0`. `NotificationWorker` lấy outbox, áp dụng mute/severity, dedup, rate limit, gọi Telegram, rồi mới đánh dấu đã xử lý. Dashboard đọc cùng SQLite nên mock mode và Wazuh mode có hành vi giống nhau.

Tách lớp như vậy giúp kiểm thử từng lỗi: kết nối, parse, lưu DB, hay gửi Telegram.

## 2. Dedup hoạt động thế nào

File: `app/services/dedup.py`.

Fingerprint là SHA-256 của ba giá trị nối với ký tự phân cách: `rule_id`, `source_ip`, `device_name`. Ba trường này trả lời “cùng kiểu phát hiện, cùng nguồn, cùng thiết bị đích hay không”. SHA-256 không dùng để bảo mật; nó tạo khóa SQLite có độ dài cố định.

Mỗi fingerprint lưu `window_started`, `last_seen`, `alert_count` và message ID của từng chat. Nếu alert đến trong `DEDUP_WINDOW_SECONDS`, counter tăng và bot gọi `editMessageText`. Nếu quá cửa sổ, nhóm mới bắt đầu và bot gửi tin mới. Alert gốc vẫn được lưu riêng trong bảng `alerts`, vì dedup chỉ giảm spam thông báo chứ không xóa bằng chứng.

`SlidingWindowRateLimiter` giữ timestamp các message gần nhất trong một `deque`. Timestamp cũ bị loại khỏi đầu hàng đợi. Khi đầy, alert bị suppress và một bộ đếm tăng; lần gửi hợp lệ tiếp theo phát summary.

## 3. Truy vấn Wazuh

File: `app/services/wazuh.py`.

Ứng dụng POST tới `/{index-pattern}/_search`, yêu cầu tối đa 500 document tăng dần theo `@timestamp`. Cursor bền vững gồm `[timestamp, _id]`. Truy vấn sau dùng `gte` để cố ý đọc chồng timestamp cuối, rồi Python bỏ mọi cặp `(timestamp, id)` nhỏ hơn hoặc bằng cursor. Khóa chính alert là `_id`, nên SQLite `INSERT OR IGNORE` là lớp chống trùng thứ hai khi ứng dụng restart.

Tại sao không chỉ dùng timestamp? Nhiều alert có thể cùng millisecond; ID là tie-breaker. Với lab, 500 alert trong cùng một millisecond là ngoài tải dự kiến. Nếu triển khai lớn hơn, chuyển sang OpenSearch Point-in-Time cùng `search_after` và `_shard_doc`.

TLS được xác minh mặc định. CA tự ký phải cung cấp bằng `WAZUH_CA_FILE`, tránh tắt TLS verification lâu dài.

## 4. Log do kẻ tấn công kiểm soát

Source IP, username, hostname, description và raw log đều có thể chứa chuỗi do attacker tạo. Vì vậy:

- Normalizer giữ chúng dưới dạng dữ liệu, giới hạn độ dài, không đánh giá HTML/JavaScript.
- SQLite luôn dùng placeholder `?` hoặc named parameter; filter chỉ ghép các clause cố định do code sở hữu.
- Jinja autoescape khi render HTML; raw log nằm trong `<pre>` nhưng vẫn được escape.
- Telegram dùng `html.escape` trước khi đặt dữ liệu vào message parse mode HTML.
- CSV thêm dấu nháy đơn trước ô bắt đầu bằng `=`, `+`, `-`, `@`, tab hoặc carriage return để spreadsheet không thực thi công thức.
- CSP, `X-Frame-Options` và `nosniff` giảm tác động nếu một output boundary bị bỏ sót.

Điểm quan trọng khi trình bày: escape phải xảy ra ở output boundary vì cùng một giá trị cần cách escape khác nhau cho HTML, Telegram HTML và CSV.

## 5. Authorization và CSRF

Bot kiểm tra `chat.id` với `ALLOWED_CHAT_IDS` trước mọi command/callback và trả `False` mà không gọi Telegram nếu không hợp lệ. Dashboard lưu username và CSRF token trong cookie session đã ký. Mọi POST so sánh token bằng `hmac.compare_digest`. Password được kiểm tra bằng PBKDF2-SHA256 với salt và số vòng lặp nằm trong hash.

## 6. Những giới hạn cần nói thật với hội đồng

- Device status dựa trên thời điểm alert cuối, chưa phải heartbeat syslog thật.
- SQLite phù hợp một container/đồ án; nhiều replica cần PostgreSQL và shared queue.
- Polling có độ trễ bằng `POLL_INTERVAL_SECONDS`; không phải streaming tuyệt đối.
- Detection quality phụ thuộc decoder/rule Wazuh. Dashboard không thay thế detection engine.
