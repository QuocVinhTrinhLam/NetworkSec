# Phase 1 Demo Script

Mục tiêu: trong khoảng 5 phút chứng minh schema chung, mock scenario, Telegram
dedup/callback và dashboard dùng cùng một SQLite state.

## Chuẩn bị

1. `cp .env.example .env`.
2. Điền `TELEGRAM_BOT_TOKEN`, `ALLOWED_CHAT_IDS` và một `SESSION_SECRET` mới.
3. Đảm bảo Docker Desktop/Engine đang chạy.
4. Chạy `docker compose up -d --build dashboard`.
5. Chờ `docker compose ps` báo `dashboard` healthy.

## 1. Seed dashboard

```bash
make seed
```

Mở `http://127.0.0.1:8000`, đăng nhập và chỉ ra timeline 24 giờ, severity,
device type, top sources, recent detections, filter và raw-log detail. Dữ liệu 7 ngày
được tạo qua cùng schema/pipeline, không ghi trực tiếp bằng SQL.

Sau khi seed xong, khởi động bot và chờ healthcheck:

```bash
docker compose up -d bot
docker compose ps
```

Thứ tự này tránh gửi hàng trăm alert lịch sử lên Telegram.

## 2. SSH brute-force và dedup

```bash
make scenario NAME=ssh_bruteforce DURATION=60
```

Scenario tạo 30 login fail trong 60 giây event-time rồi một login success. Telegram
phải có một message brute-force được edit tăng `Count`, không phải 30 message.
Chỉ ra severity, source/destination port 22, rule, MITRE T1110 và khuyến nghị.

## 3. Acknowledge và dashboard

1. Bấm **Acknowledge** trên Telegram.
2. Message được edit để hiện analyst đã acknowledge.
3. Mở alert bằng **Open dashboard** và xác nhận status/actor trong SQLite-backed UI.
4. Có thể thử **Mute rule 1h**, `/unmute 100210`, và `/status`.

## 4. Rate-limit summary

Tạm đặt `MAX_MESSAGES_PER_MINUTE=1`, restart bot, rồi chạy các scenario có dedup key
khác nhau. Bot gửi một alert riêng và một summary duy nhất được cập nhật với số alert
bị suppress cùng top rules.

## 5. Device silent

Đặt `DEVICE_SILENT_MINUTES=1`, seed một device cũ hoặc chờ quá ngưỡng. Watcher tạo
một alert `SYSTEM_DEVICE_SILENT`; alert tổng hợp không tự làm device trở lại healthy
và không bị tạo lặp cho cùng `last_seen`.

## 6. An toàn và Phase 2 boundary

- Mở alert chứa chuỗi `<script>`: dashboard hiển thị text, không thực thi HTML.
- Export CSV: cell bắt đầu bằng công thức được prefix an toàn.
- Chat ID ngoài allowlist không nhận reply.
- Đặt `ALERT_SOURCE=wazuh`: log/status báo rõ Phase 2 stub; process không crash loop.

## Dừng demo

```bash
make down
```
