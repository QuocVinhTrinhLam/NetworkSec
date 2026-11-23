# NetworkSec N4.2 · Ma trận truy vết QA

Ma trận lập từ module, route, cấu hình và bài kiểm thử trong working tree tại
`df18567`, cập nhật sau khi xác minh cả sáu bản sửa ngày 23/11/2026.
Nhãn `Covered` yêu cầu một kịch bản thực thi có kết quả. `Partially covered`
chỉ một phần điều kiện được thực thi hoặc một số kiểm tra chỉ ở mức tĩnh. `Not covered`
là thiếu kiểm tra thực thi. `Blocked` là cần môi trường hoặc quyền ngoài phạm vi QA này.
Kết quả `Covered` có thể ghi kèm một lỗi đã tái hiện. Trạng thái lỗi nằm trong
[bug tracker](BUG_REPORT.md#trạng-thái-sau-hồi-quy-ngày-23112026).

| ID | Tính năng theo mã nguồn | Bài kiểm thử hoặc bằng chứng đã đối chiếu | Kết quả |
|---|---|---|---|
| F01 | Cisco IOS, MikroTik, pfSense và dispatcher | `test_multi_vendor_parsers.py`, `test_ospf_parsers.py`, `test_qa_syslog.py` với 640 biến thể cố định seed | Covered · mẫu repo/synthetic |
| F02 | Schema Alert legacy, NormalizedEvent 1.0/1.1, identity, timezone | `test_alert_schema.py`, `test_normalizer.py`, `test_storage_api.py`, `test_qa_syslog.py` | Covered |
| F03 | Link-state 60 giây, dedup legacy, OSPF một/hai đầu, nhiều adjacency, Full, flap | `test_correlation.py`, `test_dedup.py`, `test_ospf_correlation.py`, lịch trình synthetic có Full cũ, replay và nhiều Area | Covered |
| F04 | Spool JSONL, DLQ, receipt, health, checkpoint, Loki→PG, restart và retry | `test_processor.py`, `test_processor_healthcheck.py`, `test_storage_writer.py` và spool-to-backend native. Parser fault lặp, restart/idle còn block, phục hồi sau tiến triển, OSPF reconcile và heartbeat hết hạn. | Covered · QA-04 đã sửa |
| F05 | SQLite legacy, mock/replay ingest và thiết bị im lặng | `test_database.py`, `test_ingestion.py`, `test_adapters.py`, `test_mock_*.py`, `test_silent_devices.py` | Covered |
| F06 | PostgreSQL migration 001–005, incident/evidence/history, ACK/Resolve, tranh chấp, truy vấn và outbox | `integration/test_postgres_ospf_lifecycle.py`, `integration/test_phase5_storage.py` trên PostgreSQL 17.7 tạm. Hai thứ tự khóa, retry và rollback đã chạy. | Covered · QA-05 đã sửa |
| F07 | Loki push, parser response, cursor, lọc, schema version và lỗi transport | `test_storage_loki.py`, `integration/test_phase5_storage.py`, `integration/test_ospf_loki_queries.py`. Loki 3.7.0 thật, MockTransport, envelope/stream sai kiểu, kết quả rỗng, hỗn hợp schema/replay và 760 event cùng timestamp. | Covered · QA-01/03 đã sửa |
| F08 | Toàn bộ API JSON và bảo vệ session/CSRF, validation, storage unavailable | `test_storage_api.py` bao phủ 7 route, fake storage và tích hợp PostgreSQL/Loki. Cursor ngoài khoảng trả 400, late ACK trả 200 với trạng thái hiện tại, lỗi protocol Loki trả 502. | Covered · QA-01/02/03/05/06 đã sửa |
| F09 | HTML login/logout, cookie, queue, tìm kiếm, CSV, evidence, ACK/Resolve, HTMX, trạng thái trống/lỗi | `test_auth.py`, `test_dashboard.py`, `test_operational_dashboard.py`, 6 Playwright test với Uvicorn và Edge localhost | Covered |
| F10 | Grafana datasource, provisioning, panel cũ/OSPF, LogQL, dữ liệu trống | JSON và mount tĩnh, 6 truy vấn trên Loki thật sau thay macro, empty response mock | Partially covered · thiếu Grafana runtime |
| F11 | Telegram command/callback, allowlist, severity, dedup/rate/cooldown, chỉnh thẻ Down/Full, timeout | `test_bot.py`, `test_telegram_bot.py`, `test_aggregated_notifications.py`, `test_ospf_notifications.py`, PostgreSQL cô lập với gateway fake | Covered · mock Telegram |
| F12 | rsyslog TCP/UDP → raw/envelope, generator, health và Compose restart | Cấu hình và 5514 kiểm tra tĩnh, generator localhost, hai test socket/stack opt-in không chạy | Blocked · Docker daemon |
| F13 | Bảo mật đầu vào và trình bày, headers, giới hạn, CSV, SQL, xử lý bí mật | Session/auth, CSRF ASCII/Unicode/thiếu token, mẫu secret lồng trong lỗi validation, HTML escape, SQL literal, CSV formula guard và log giả. | Partially covered · QA-02/06 đã sửa, proxy/TLS chờ nghiệm thu |
| F14 | Config từ environment, Dockerfile, Compose profiles, migrations và CI | `compose config --quiet`, đọc Dockerfile, YAML và workflow; migrations chạy trên PostgreSQL tạm | Partially covered · image runtime chưa chạy |
| F15 | Benchmark, catalog và kịch bản demo | `test_benchmark.py`, `test_catalog.py`, `test_dashboard.py`, Playwright legacy và benchmark synthetic có giới hạn | Covered · giới hạn vào mock |
| F16 | R1–R2 live OSPF, Ubuntu Compose và Telegram thực | Chỉ dùng checklist triển khai, `test_gns3_phase7.py` đọc snapshot cũ | Blocked |
| F17 | Giới hạn tại reverse proxy và hành vi truy cập qua HTTPS production | Đọc middleware, bind và cấu hình cookie. Không có proxy chạy trong môi trường test. | Not covered |
| F18 | Down → Loki/correlation → incident → Dashboard/ACK → Full → Resolve → Telegram | `test_ospf_spool_to_loki_incident_dashboard_and_telegram` đối chiếu từng cursor với `page_size=1` ở trạng thái mở, ACK đang chờ, và sau recovery. Bao gồm replay khác `received_at`, restart, Full cũ và ACK muộn cùng luồng. [Test](../../tests/integration/test_postgres_ospf_lifecycle.py#L704) | Covered · spool synthetic, Loki/PostgreSQL thật, Telegram fake |

## HTTP inventory

| Nhóm | Method và path được đăng ký |
|---|---|
| Health và đăng nhập | `GET /health`, `GET /login`, `POST /login`, `POST /logout`, `GET /` |
| Dashboard | `GET /dashboard`, `GET /partials/dashboard` |
| HTML alerts | `GET /alerts`, `GET /alerts/export.csv`, `GET /alerts/{id}`, `POST /alerts/{id}/ack`, `POST /alerts/{id}/resolve` |
| HTML event và demo | `GET /events`, `GET /devices`, `GET /scenarios`, `POST /scenarios`, `GET /scenarios/export.csv` |
| API JSON | `GET /api/v1/storage/health`, `GET /api/v1/events`, `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}`, `GET /api/v1/alerts/{id}/evidence`, `POST /api/v1/alerts/{id}/acknowledge`, `PATCH /api/v1/alerts/{id}/status` |
| Framework | `GET /openapi.json`, `GET /docs`, `GET /docs/oauth2-redirect`, `GET /redoc`, static assets dưới `/static` |

API JSON được kiểm tra cả nhánh chưa đăng nhập và hành vi theo từng hợp đồng.
`/storage/health` có healthy/degraded. `/events` có version, lọc, cursor và lỗi
storage. `/alerts` có lọc, phân trang và queue mặc định. Detail/evidence có ID
hợp lệ, ID sai dạng và ID không tồn tại. Hai mutation có CSRF, lỗi JSON, body
thiếu/quá giới hạn, chuyển trạng thái và 404. HTML kết hợp TestClient với thao
tác trình duyệt; static/docs smoke test chỉ đọc response.
