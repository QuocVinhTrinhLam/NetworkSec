# Phase 2 — Syslog Collection

## Data flow

```text
GNS3 devices / Python generator / Loghub files
                 | TCP newline framing or UDP datagram
                 v
         rsyslog imtcp + imudp :5514
                 |
                 v
        disk-assisted action queue
        /var/spool/rsyslog
                 |
                 v
        immutable raw message stream
        /var/log/networksec/raw.log
                 |
                 +--> versioned processor envelope
                      /var/log/networksec/processor.jsonl
```

rsyslog ghi property `$rawmsg` và chỉ thêm ký tự xuống dòng làm record delimiter. Raw evidence không bị
parse, normalize hoặc sửa. Cùng ruleset tạo thêm JSONL envelope version `1.0` bằng rsyslog JSON escaping;
envelope chứa `received_at`, `source_host`, `source_ip`, `$rawmsg` đầy đủ và `parse_message` sau PRI
chuẩn để worker không phải suy đoán
metadata từ filename. Raw và envelope cùng nằm trên `syslog-raw`; mỗi output có disk-assisted action
queue riêng trong `syslog-queue`.

## Transport semantics

- TCP dùng newline framing, có backpressure và là lựa chọn mặc định.
- UDP dùng một datagram cho mỗi event. UDP không có acknowledgement/backpressure; khi socket hoặc queue quá tải, event có thể mất. Sequence ID của generator giúp phát hiện gap.
- Plain TCP/UDP không cung cấp confidentiality hoặc sender authentication. Chỉ expose listener trên mạng lab tin cậy; mặc định Compose bind vào `127.0.0.1`. TLS/RELP nằm ngoài Phase 2.
- Giới hạn message mặc định là 32 KiB. Generator từ chối record rỗng, record nhiều dòng và record vượt giới hạn trước khi gửi.

## Buffering và recovery

Action queue là `LinkedList` disk-assisted. Các biến sau điều chỉnh mà không sửa config template:

| Biến | Mặc định | Ý nghĩa |
|---|---:|---|
| `RSYSLOG_QUEUE_SIZE` | 10000 | Số slot message |
| `RSYSLOG_QUEUE_HIGH_WATERMARK` | 8000 | Bắt đầu ghi queue xuống disk |
| `RSYSLOG_QUEUE_LOW_WATERMARK` | 2000 | Quay lại memory mode |
| `RSYSLOG_QUEUE_DISK_MB` | 256 | Giới hạn queue disk |
| `RSYSLOG_QUEUE_WORKERS` | 1 | Worker ghi raw spool |
| `RSYSLOG_QUEUE_CHECKPOINT_INTERVAL` | 100 | Tần suất checkpoint |
| `RSYSLOG_RETRY_SECONDS` | 2 | Khoảng nghỉ khi output bị suspended |

Entrypoint kiểm tra type/range và quan hệ `low < high < size`, render config vào tmpfs, sau đó chạy `rsyslogd -N1` trước khi khởi động daemon. Output action retry vô hạn, lưu queue khi shutdown và sync queue files. TCP sender sẽ chậm lại khi queue đầy; UDP vẫn có thể mất do bản chất giao thức.

Không chạy `docker compose down -v`: lệnh đó xóa cả raw spool và queue recovery. Theo dõi dung lượng volume vì raw log không tự xóa trong Phase 2.

## Python Syslog Generator

Sinh 100 RFC 5424 events qua TCP ở 10 events/giây:

```bash
docker compose up -d --wait rsyslog
docker compose --profile syslog-tools run --rm syslog-generator
```

Chạy trực tiếp với sequence bắt đầu tùy chọn:

```bash
python -m app.syslog_generator --protocol tcp --count 100 --rate 25 --start-sequence 5000
```

`--rate 0` tắt pacing. Khi TCP reconnect sau lỗi, message hiện tại có thể được gửi lại; downstream phải dùng sequence ID/idempotency để nhận biết duplicate.

Replay file Loghub hoặc fixture line-oriented mà không decode/re-encode payload:

```bash
python -m app.syslog_generator \
  --protocol tcp \
  --rate 50 \
  --count 0 \
  --loghub-file fixtures/logs/cisco-ios.log
```

`--count 0` nghĩa là replay toàn bộ file; giá trị dương giới hạn số record.

## Error handling và kiểm thử

- Generator retry socket theo `SYSLOG_SEND_RETRIES`/`SYSLOG_RETRY_DELAY_SECONDS`, trả exit code 1 khi hết retry và không in payload.
- rsyslog báo config/range error ra stderr và không khởi động với config không hợp lệ.
- Unit test mở TCP/UDP socket thật trên loopback để xác minh framing, datagram, pacing, sequence và raw Loghub bytes.
- Integration test Docker gửi cả TCP/UDP vào rsyslog thật và đọc raw spool để so sánh nguyên message. Chạy bằng:

```bash
docker compose up -d --wait rsyslog
RUN_SYSLOG_INTEGRATION=1 python -m pytest -m syslog_integration tests/integration
docker compose stop rsyslog
```

Không cần Kafka hoặc Redis ở boundary này: rsyslog đã cung cấp persistent queue cho một raw-file sink. Chỉ xem xét broker khi có nhiều consumer độc lập, retention/replay phức tạp hoặc throughput test chứng minh queue hiện tại không đủ.
