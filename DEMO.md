# Kịch bản demo

## Chuẩn bị

1. Chạy `docker compose up -d --build` và mở dashboard.
2. Đăng nhập, mở đồng thời Telegram và trang Alerts.
3. Kiểm tra `/status` trên bot.
4. Giữ video demo dự phòng và bản sao volume/config.

## Demo 1 — alert mới

```bash
docker compose exec monitor python -m app.mock_generator --count 1 --interval 0
```

Trong vòng tối đa 15 giây, chỉ ra alert trên Telegram, mức severity, source/destination, rule và recommended response. Mở alert từ nút dashboard và giải thích raw log đã được escape.

## Demo 2 — dedup

```bash
docker compose exec monitor python -m app.mock_generator --count 8 --interval 0.2 --duplicate-every 2
```

Chỉ ra Telegram cập nhật `Count` trên tin nhắn cùng fingerprint thay vì tạo spam. Giải thích fingerprint gồm rule ID, source IP và device; cửa sổ mặc định là 60 giây.

## Demo 3 — acknowledge và mute

1. Nhấn **Acknowledge** trong Telegram, tải lại alert trên dashboard.
2. Nhấn **Mute 1h** hoặc chạy `/mute 100210 60`.
3. Sinh lại sự kiện cùng rule và chứng minh dashboard vẫn lưu bằng chứng nhưng Telegram không gửi.

## Demo 4 — attack scenarios

1. Mở Attack scenarios.
2. Ghi công cụ, kỹ thuật, expected rule, detected và detection time.
3. Export CSV và dùng file này tính detection rate/thời gian trung bình trong báo cáo.

## Kết thúc

Mở Devices để chỉ ra trạng thái silent, Overview để chỉ ra top source/rule, rồi chạy `/stats`. Nếu lab thật lỗi, lặp lại toàn bộ bằng mock mode và video dự phòng.
