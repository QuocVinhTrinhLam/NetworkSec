# NetworkSec N4.2 · Báo cáo QA độc lập

## Hồi quy sau khi xử lý bốn lỗi còn lại

**Ngày 23/11/2026 · Đánh giá PARTIAL.** Cả sáu lỗi đã xác nhận đều có bản sửa và
bài hồi quy đạt. Working tree đủ điều kiện chuyển sang kiểm thử Compose/Ubuntu
cô lập. Kết quả hiện tại mới xác minh phần mềm trên Windows với dịch vụ native,
dữ liệu synthetic và Telegram fake. Các bài nghiệm thu live GNS3, runtime Linux
Compose và Grafana server cần bằng chứng riêng.

### Tái hiện và thay đổi

Git base `df185672055790ea027ea120ecfc304a7e450d36`. Các thay đổi trước đó trong
working tree được giữ lại. Chạy cùng bốn node ID với `--runxfail` trước và sau
khi sửa, khi marker vẫn còn. Kết quả chuyển từ **4 failed** sang **4 passed**.
Chỉ gỡ marker sau khi cả bốn test gốc đạt.

| ID | Trước | Sau và bằng chứng |
|---|---|---|
| QA-03 | Adapter gọi `.get()` trên JSON không phải object. API trả 500. | Kiểm tra envelope, `data.result`, stream và entry. Dùng `StorageError` cho lỗi protocol; API trả 502 với thông báo chung. Kết quả rỗng hợp lệ và dòng log có JSON/schema hỏng vẫn theo đúng luồng đọc và dedup. [Adapter](../../app/storage/loki.py#L136), [API test](../../tests/test_storage_api.py#L426). |
| QA-04 | Parser lỗi ngoài phần đánh dấu health. Restart và heartbeat idle có thể đặt lại trạng thái trước khi xử lý record. | Worker đánh dấu `blocked` ngay, giữ offset và tiếp tục retry. Restart và idle giữ block. Tiến triển được ghi sau xử lý hoặc DLQ; reconcile OSPF thành công chỉ gỡ block do reconcile. Test kiểm tra lỗi lặp, restart và heartbeat hết hạn. [Worker](../../app/processor/worker.py#L88), [test](../../tests/test_processor.py#L449). |
| QA-06 | Handler mặc định đưa giá trị mật khẩu vào `detail[].input` của response 422. | Handler giữ vị trí, mã và thông báo lỗi đã lọc cho từng trường. Raw input và context được bỏ. Test kiểm tra nhiều trường lỗi, secret lồng, JSON sai, login hợp lệ và log ứng dụng. [Handler](../../app/main.py#L83), [test](../../tests/test_storage_api.py#L610). |
| QA-02 | `compare_digest` ném lỗi khi được truyền chuỗi không phải ASCII. | Token Unicode sai, surrogate và token thiếu trong request còn lại hợp lệ bị từ chối với 403. Token ASCII vẫn đối chiếu constant-time. [Validator](../../app/web/auth.py#L49), [test](../../tests/test_storage_api.py#L563). |

### Hồi quy và triển khai

| Kiểm tra | Kết quả |
|---|---|
| Bộ test đích | **87 đạt**. |
| Pytest ngoài trình duyệt | **300 đạt, 2 skipped, 0 xfail**. Coverage tổng **84%** với branch tracking. Có 25 bài native với PostgreSQL/Loki. |
| Playwright | **6 đạt** trên Edge với FastAPI localhost và dữ liệu test. |
| Tổng hai lượt | **306 đạt, 2 skipped, 0 xfail**, 0 lỗi bất ngờ. |
| QA-01, QA-05 và OSPF | Repro mock/native của cursor, hai thứ tự khóa ACK/Resolve, và luồng Down → ACK → Full → Resolve qua PostgreSQL/Loki đều đạt. |
| Kiểm tra tĩnh | Ruff lint/format, mypy, `pip check`, `git diff --check` và Compose config với `.env.example` đều đạt. |

PostgreSQL 17.7, Loki 3.7.0 và SQLite dùng dữ liệu tạm cô lập. Hai bài bỏ qua là
`test_rsyslog_collection.py` và `test_processor_pipeline.py`, cần Docker daemon
cho rsyslog TCP/UDP và restart container. Lượt này xác thực Compose model qua CLI,
với các profile tùy chọn. Docker Linux engine pipe chưa khả dụng.

Các rủi ro triển khai còn lại gồm version image PostgreSQL mục tiêu, giới hạn
phân trang Loki khi timestamp có quá nhiều record, theo dõi health khi nguồn spool
chưa trở lại, và proxy/TLS ở môi trường đích. Kết quả telemetry hiện dùng log mẫu.
Cần chạy hai bài Compose đang bỏ qua, smoke test Grafana runtime và thu mẫu
Down/Full thật từ R1/R2 trước khi xác nhận nghiệm thu live. [Bug tracker](BUG_REPORT.md) ·
[Ma trận](TEST_MATRIX.md)

Tệp cập nhật thuộc lượt này:

- App `app/storage/loki.py`, `app/processor/worker.py`, `app/processor/state.py`,
  `app/main.py`, `app/web/auth.py` và `app/web/routes.py`.
- Test `tests/test_storage_loki.py`, `tests/test_storage_api.py`, `tests/test_processor.py`,
  `tests/test_processor_healthcheck.py` và `tests/test_auth.py`.
- QA `docs/qa/BUG_REPORT.md`, `docs/qa/FULL_MOCK_QA_REPORT.md` và `docs/qa/TEST_MATRIX.md`.

Minh chứng tạm trong `networksec-qa-four-fixes-a92c6135011a4ce88a46e64d5eb0f339`
dưới thư mục tạm Windows, gồm `before.log`, `after.log`, `targeted.log`,
`regression.log`, `browser.log` và `evidence/`.

---

## Mốc hồi quy sau bản sửa QA-01 và QA-05

**Ngày 23/11/2026 · Đánh giá phần mềm PARTIAL.** Hai lỗi High đã qua xác minh chung.
Không quan sát lỗi hồi quy ngoài bốn lỗi đã biết trong các kịch bản được chạy. Working
tree đủ điều kiện chuyển sang kiểm thử Docker/Ubuntu cô lập với dữ liệu giả.

**Sẵn sàng triển khai live GNS3 · PARTIAL.** Chưa có bằng chứng runtime Compose,
Ubuntu và Syslog từ R1/R2 thật. Các điều kiện này phải được xác minh trước khi
nghiệm thu triển khai. [Bug tracker](BUG_REPORT.md) · [Ma trận](TEST_MATRIX.md)

### Working tree và môi trường

- Git base `df185672055790ea027ea120ecfc304a7e450d36`. Trước lượt này có 44 tệp
  tracked đã sửa, 24 tệp dự án untracked và `.vscode/settings.json` đã có sẵn.
  Đã kiểm tra `git status`, diff và index. Bản sửa QA-01 nằm ở adapter Loki.
  Bản sửa QA-05 nằm ở guard ACK khóa hàng của adapter PostgreSQL.
  [Loki](../../app/storage/loki.py#L77), [PostgreSQL](../../app/storage/postgres.py#L582)
- Windows với Python 3.12.10, PostgreSQL 17.7 và Loki 3.7.0 native trên loopback,
  mỗi service có thư mục dữ liệu mới. Bài PostgreSQL dùng schema riêng; SQLite,
  coverage và ảnh Playwright ở thư mục tạm. Edge chạy các bài Playwright sẵn có với
  route ứng dụng chỉ trên localhost. Telegram dùng gateway fake.
- Đợt này cập nhật ba tệp QA và mở rộng duy nhất
  `tests/integration/test_postgres_ospf_lifecycle.py`. Các tệp ứng dụng và test
  có diff từ trước được kiểm kê bên dưới. Báo cáo gốc được lưu ở phần tiếp theo
  để giữ nguyên mốc trước khi sửa.

### Kết quả thực thi

| Hạng mục | Bằng chứng |
|---|---|
| Pytest ngoài trình duyệt | **273 đạt, 2 skipped, 4 xfailed**, 6 e2e chạy riêng. Coverage tổng **84%** với branch tracking của repo. |
| Tích hợp native trong 273 test | **25 đạt**. Module PostgreSQL có 21 bài, gồm luồng với Loki và gateway Telegram fake. Module Loki có 3 bài. Còn 1 round-trip legacy dùng cả hai backend. |
| Playwright | **6 đạt** trên Edge, gồm 5 luồng legacy và 1 luồng operational. Lưu 11 ảnh minh chứng thành công. |
| Tất cả kịch bản pytest đã chọn | **279 đạt, 2 skipped, 4 xfailed**, 0 lỗi bất ngờ. |
| Tái hiện riêng `--runxfail` | **4 failed đúng kỳ vọng**. QA-02, QA-03, QA-04 và QA-06 vẫn mở. Lượt này tách riêng khỏi tổng hồi quy. |
| Kiểm tra tĩnh | Ruff lint/format, mypy (61 tệp app), `pip check`, `git diff --check` và `git diff --cached --check` đều đạt. |
| Docker Compose | CLI 5.7.0 xác thực model với `.env.example`, cả `--no-interpolate` và tất cả profile. Linux engine pipe không khả dụng. |

Pytest ghi cảnh báo deprecation từ Starlette TestClient trong hai lượt chính.
Minh chứng tạm nằm trong `networksec-postfix-7269f16a44ee4736918a5f86913ba265`
dưới thư mục tạm của Windows, gồm `regression.log`, `browser.log`,
`open-defects.log`, `performance.jsonl` và `evidence/`.

### Kiểm thử quy trình OSPF và bảo mật

Bài tích hợp mở rộng bắt đầu từ envelope Syslog synthetic. Hai Down được chuẩn
hóa thành event 1.1, ghi vào Loki và gộp thành một incident PostgreSQL.
Dashboard hiển thị bằng chứng và operator ACK với note. Sau khi dựng lại worker
từ checkpoint, Full cũ và Full thiếu một đầu vẫn giữ incident mở. Full hợp lệ
của đầu còn lại đóng cùng incident, lưu nguồn `ospf_recovery` và giữ ACK.

API đọc Loki với `page_size=1` ở cả ba mốc Down, sau ACK khi còn chờ Full, và
sau Resolve. Các bản replay khác `received_at` vẫn giữ cùng event ID. Bài test
đối chiếu thứ tự, cursor tiến triển, hết trang, sáu event ID duy nhất và tham
chiếu bằng chứng. ACK gửi muộn sau recovery trả đúng bản ghi `resolved` đã có.
Gateway fake nhận một thẻ Down và một lần cập nhật recovery trên cùng thẻ.
[Test tích hợp](../../tests/integration/test_postgres_ospf_lifecycle.py#L704)

Hồi quy còn chạy auth/session và phân quyền truy cập API, CSRF, tìm kiếm literal
trên PostgreSQL, escape HTML cho evidence/note, CSV formula guard, hai thứ tự
ACK/Resolve với khóa thật, rollback outbox, retry sau lỗi storage và replay
qua restart. Các bài Loki xác minh thêm phân trang nhóm cùng timestamp,
cursor cũ, schema 1.0/1.1 và 400 cho cursor sai hoặc ngoài khoảng thời gian.

### Lỗi còn mở và các bài bỏ qua

| ID hoặc bài | Kết quả hiện tại |
|---|---|
| QA-01 · High | Đã sửa. Repro mock và Loki thật đọc đủ trang sau replay. |
| QA-05 · High | Đã sửa. Repro PostgreSQL giữ `resolved`; cả hai thứ tự tranh chấp và recovery tự động đều đạt. |
| QA-02 · Low | `test_qa_non_ascii_csrf_gets_normal_forbidden_response` · CSRF Unicode sai trả 500 thay vì 403. |
| QA-03 · Medium | `test_qa_loki_rejects_non_object_response_as_storage_error` · Loki JSON array gây `AttributeError`. Thử riêng qua TestClient với Loki mock xác nhận Events API trả 500 thay vì 502. |
| QA-04 · Medium | `test_qa_unexpected_parser_fault_keeps_offset_and_marks_worker_blocked` · health vẫn `healthy` ngay sau parser exception. Khôi phục worker xử lý tiếp record trong test. |
| QA-06 · Low | `test_qa_validation_error_does_not_echo_login_password` · response 422 phản chiếu marker mật khẩu synthetic trong `detail[].input`. |
| `test_rsyslog_collection.py` | Skipped. Cần `RUN_SYSLOG_INTEGRATION=1` và rsyslog Compose đang chạy. Không có Docker daemon trong lượt này. |
| `test_processor_pipeline.py` | Skipped. Cần `RUN_PROCESSOR_INTEGRATION=1` với stack Compose cô lập, gồm bước restart container. Không có Docker daemon trong lượt này. |

Không còn lỗi High/Critical đã xác nhận. QA-03 và QA-04 là rủi ro vận hành ưu tiên
tiếp theo. QA-06 cần xử lý trước lưu response qua hệ thống có credential thật.
QA-02 là lỗi nhất quán HTTP đối với đầu vào sai dạng. [Triệu chứng và ưu tiên](BUG_REPORT.md)

### Phép đo và giới hạn

Chạy lại harness hiện có trên Windows với SQLite tạm và writer giả. Tải link-state
có 10% replay. RSS là mẫu cuối công đoạn. Một lượt đo chưa đủ kết luận thay đổi
hiệu năng ở đường đọc Loki hoặc tại PostgreSQL.

| Tải | Worker link-state gồm replay | p95 worker | RSS cuối worker | OSPF correlation trên một adjacency · throughput / p95 |
|---:|---:|---:|---:|---:|
| 100 | 44,12 record/s | 28,915 ms | 58,8 MiB | 96,41 record/s / 12,529 ms |
| 1.000 | 46,01 record/s | 29,913 ms | 59,3 MiB | 52,47 record/s / 31,705 ms |

Hai tải cho đúng 100 và 1.000 ID duy nhất với 110 và 1.100 lần gọi writer fake.
Hiệu năng OSPF giảm khi journal của một adjacency dài hơn. Mốc gốc đã chạm timeout
khi chạy pipeline 10.000 event; lượt này chỉ chạy tải đến 1.000. Adapter phân trang
Loki trả 502 khi vượt giới hạn 5.000 dòng/lần hoặc 24 lần đọc/trang mà chưa xác định
được biên. Loki dùng dữ liệu hiện tại ở mỗi query; log đến muộn có thể ảnh hưởng
tập kết quả ở các trang đang đọc. Chưa đo soak test Ubuntu hoặc tải đồng thời của
ACK và truy vấn Loki.

### Điều kiện để nghiệm thu runtime

1. Dùng một Compose project và volume riêng trên môi trường kiểm thử Ubuntu.
   Xác nhận rsyslog TCP/UDP 5514, permissions, cấu hình bind và processor restart
   bằng hai bài đang skipped. Kiểm tra image PostgreSQL mục tiêu 17.12.
2. Smoke test Grafana runtime, provisioning, datasource và time-range macro.
   Sáu biểu thức LogQL đã chạy trên Loki 3.7.0 với giá trị macro thay thế.
3. Xác nhận mapping R1 CHR/R2 IOSv Area 0 từ log Down/Full thực đã khử dữ liệu
   nhạy cảm. Đo restart, loss, backlog và đường Syslog khi transit bị ngắt.
   Test snapshot GNS3 hiện chỉ xác nhận metadata topology cũ.
4. Xử lý các lỗi còn mở theo ưu tiên trước nghiệm thu với credential/dữ liệu thật.
   Kiểm tra proxy và HTTPS trên môi trường đích. Xác minh Telegram thật chỉ trong
   đợt nghiệm thu được duyệt. Khi triển khai cuốn chiếu, tiến trình cũ vẫn có thể
   ghi theo quy tắc ACK cũ; đối soát riêng các incident từng bị mở lại.

### Kiểm kê các tệp app và test có khác biệt so với HEAD

| Thư mục | Tệp |
|---|---|
| `app/bot/` | `__main__.py`, `aiogram_runtime.py`, `formatter.py`, `notification_models.py`, `ospf.py` |
| `app/parsers/` | `cisco_ios.py`, `mikrotik.py`, `ospf.py` |
| `app/processor/` | `state.py`, `worker.py` |
| `app/schemas/` | `api.py`, `correlation.py`, `event.py` |
| `app/services/` | `correlation.py`, `ospf_correlation.py`, `storage.py` |
| `app/storage/` | `base.py`, `loki.py`, `postgres.py`, `unavailable.py` |
| `app/templates/` | `alert_detail.html`, `alerts.html`, `dashboard.html`, `events.html`, `partials/alert_evidence.html`, `partials/dashboard_content.html`, `partials/operational_dashboard.html` |
| `app/web/` | `api.py`, `routes.py` |
| `tests/integration/` | `test_ospf_loki_queries.py`, `test_postgres_ospf_lifecycle.py` |
| `tests/` | `qa_benchmark.py`, `qa_synthetic.py`, `test_e2e_playwright.py`, `test_multi_vendor_parsers.py`, `test_operational_dashboard.py`, `test_ospf_correlation.py`, `test_ospf_notifications.py`, `test_ospf_observability.py`, `test_ospf_parsers.py`, `test_processor.py`, `test_processor_infrastructure.py`, `test_qa_syslog.py`, `test_storage_api.py`, `test_storage_loki.py` |

---

## Mốc QA ban đầu trước hai bản sửa

**Ngày 23/11/2026 · Đánh giá lịch sử FAIL cho sẵn sàng triển khai.**

Hồi quy chạy trên working tree hiện tại cho **253 test đạt ngoài trình duyệt,
6 test Playwright đạt, 2 test Docker bỏ qua và 7 xfail có chủ đích**. Lần chạy
riêng với `--runxfail` tái hiện đầy đủ 7 test lỗi, tương ứng **6 lỗi xác nhận**.
Hai lỗi ưu tiên cao ảnh hưởng trực tiếp đến vận hành. Một ACK đến muộn có thể
mở lại incident đã Resolve. Một bản replay có thể làm mất cursor và che sự kiện
đã ghi trong Loki khỏi các trang sau. Đã tái hiện cả hai trên backend cục bộ thật.

[Ma trận tính năng và route](TEST_MATRIX.md) ·
[Bằng chứng, cách tái hiện và đề xuất sửa](BUG_REPORT.md)

## Phạm vi và môi trường

- Git base `df18567` (`fix(ci): make Windows RSS helper portable`). Working tree
  khi bắt đầu có 43 tệp tracked đã sửa, 18 tệp dự án untracked của các phase
  OSPF trước và thư mục `.vscode/` có sẵn. Phép đo áp dụng cho source đang có
  trong working tree, gồm cả phần chưa commit. Lần QA này chỉ thêm hoặc cập
  nhật tệp kiểm thử và tài liệu QA.
- Windows 11 Pro N với 8 CPU logic và 15,93 GiB RAM. Python 3.12.10 trong
  `.venv`, Docker Compose CLI 5.7.0, Playwright Python với Edge có sẵn.
  Hypothesis/psutil không có. Fuzz dùng `random.Random(4206)` và phép đo RSS
  dùng helper Windows của repo.
- Khởi tạo PostgreSQL **17.7** trong data directory mới, bind localhost, và
  dùng schema riêng cho mỗi bài. Loki **3.7.0** dùng data directory mới trên
  localhost. Cả hai dùng binary cục bộ đã sẵn có. PostgreSQL của Compose
  được khai báo 17.12 và cần xác minh riêng khi chạy image.
- Mỗi bộ dùng SQLite, spool, coverage và ảnh browser trong thư mục tạm. Các
  request trình duyệt trong test được giới hạn vào localhost. Telegram dùng
  fake hoặc `AsyncMock`, kể cả lỗi token, timeout và retry. `.env` đang dùng,
  credential thật, DB hiện hữu và Docker volume hiện hữu nằm ngoài chiến dịch.

## Kiểm kê thực hiện

Đã đọc các entry point FastAPI, processor, Telegram, mock, syslog generator,
healthcheck, benchmark và password hash. Đã đối chiếu parser, schema, SQLite,
PostgreSQL, Loki, Jinja/HTMX, cấu hình Grafana/rsyslog, dependencies, Dockerfile,
Compose, mẫu biến môi trường, tập fixture và migration 001–005. FastAPI đọc
settings từ environment. Dashboard dùng PostgreSQL trong operational mode và
SQLite cho legacy. Compose mặc định dùng loopback cho cổng quản trị và TCP/UDP
Syslog 5514. `ospf.links` mặc định rỗng. Xem
[Settings](../../app/config.py), [Compose](../../compose.yaml) và
[correlation rules](../../config/correlation_rules.yaml).

CI dùng quyền `contents: read`, pin action checkout/setup Python và cấu hình
bài Syslog opt-in. Pipeline QA này xác minh cục bộ lint, type, test và Compose
model. CI runner, build image và chính sách mạng Ubuntu cần kiểm tra riêng.
Không thực hiện tra cứu advisory qua mạng. `pip check` xác nhận tính nhất quán
của dependency đang cài. [Workflow](../../.github/workflows/quality.yml)

## Kết quả thực thi

| Lớp xác minh | Kết quả | Phạm vi |
|---|---|---|
| Baseline độc lập trước khi thêm test | 207 đạt, 18 skipped, 5 e2e được chọn riêng | DB/Loki/Docker opt-in tắt để lấy baseline mock |
| Pytest mock-only cuối | 235 đạt, 22 skipped, 5 xfail, 6 e2e chạy riêng | 20 test native opt-in và 2 test Docker bị bỏ qua trong lượt mock-only |
| Pytest hợp nhất cuối | 253 đạt, 2 skipped, 7 xfail, 6 e2e được chạy riêng | Coverage tổng 84% theo cấu hình branch coverage của repo |
| Phần native trong Pytest hợp nhất | 18 đạt, 2 xfail | Migration từ schema cũ, transactional rollback, cạnh tranh ACK/Resolve, lookup evidence/SQL literal, luồng spool với hai backend, legacy round-trip, sáu truy vấn Grafana trên Loki và tái hiện QA-01/05 |
| Playwright | 6 đạt | 5 legacy và 1 operational. Uvicorn localhost, dữ liệu test, các thao tác login/logout, session, queue, OSPF metadata, timeline, ACK/Resolve, 403, 404, HTMX, filter/empty và CSV |
| Tái hiện với `--runxfail` | 7 failures đúng vị trí kiểm tra | 6 lỗi duy nhất. QA-01 có bài mock và native |
| Ruff lint và format, mypy, pip check, git diff --check | PASS | mypy kiểm tra 61 tệp app. Pytest có một cảnh báo deprecation Starlette TestClient |
| Compose và observability | PASS tĩnh, PASS truy vấn Loki | `compose config --quiet` với `.env.example` và các profile. Kiểm tra JSON provisioning, datasource, mount, nhãn và panel. Sáu biểu thức OSPF chạy trên Loki với macro được thay bằng giá trị cụ thể |

Pytest có các bài kiểm tra rõ ranh giới storage. Adapter fake và
`httpx.MockTransport` xác minh hợp đồng, fault và cách làm sạch lỗi. Backend
loopback thật xác minh migration, giao dịch, SQL, LogQL và dedup. Playwright
operational dùng fake alert store để kiểm tra trình bày. Bộ native xác minh
nghiệp vụ persistence riêng. [Ma trận](TEST_MATRIX.md)

### Dữ liệu synthetic và độ bền

`tests/qa_synthetic.py` dùng tên QA và dải địa chỉ tài liệu. Dataset bao gồm
legacy link/config/port-security, RouterOS login, pfSense filterlog, OSPF
Down/Full/trạng thái trung gian, bản tin khuyết và Unicode. 640 biến thể seeded
kiểm tra dispatcher trả kết quả an toàn, bảo toàn raw input và UTC cho record
hợp lệ. Lịch trình OSPF có ba Router ID, hai Area, Down cách nhau hơn 60 giây,
Full cũ đến muộn, restart, replay và flap mở incident mới. Các bài sẵn có
kiểm tra mapping rỗng, xung đột và mapping mơ hồ.

Fault injection kiểm tra Loki timeout, lỗi PostgreSQL sau khi ghi Loki,
Telegram timeout, parser exception, spool malformed/quá giới hạn và replay
sau restart. Các ca retry thành công giữ trạng thái và event ID, còn lỗi
health khi parser ném exception được ghi riêng ở QA-04. Ghi nhận concurrency
trên PostgreSQL thật cho thấy history có thứ tự nhất quán, nhưng ACK muộn có
thể đảo trạng thái kết thúc ở QA-05.

### Bảo mật và hợp đồng HTTP

- Cả 7 JSON route bảo vệ đều từ chối khi thiếu phiên. Cookie lỗi bị từ chối
  trên alert queue API và Dashboard. Kiểm tra login sai, đổi CSRF sau login,
  logout, CSRF đúng/sai, status/body validation, ID bất hợp lệ, 404, 503 và
  phản hồi health. QA-02 và QA-06 tái hiện bằng request synthetic của TestClient.
- Kiểm tra CSP, frame policy, `nosniff`, HttpOnly và SameSite. Log và note
  được hiển thị dưới dạng text trong các trang đã thử. CSV guard xử lý dấu
  công thức kể cả whitespace/BOM. PostgreSQL trên localhost xử lý dấu nháy
  và `%_` dưới dạng chuỗi tìm kiếm literal.
- Lỗi storage trả thông điệp chung cho caller. Lỗi Telegram Unauthorized
  giả lập được quy đổi thành permanent error với thông báo đã làm sạch và
  không retry. Kiểm tra log chỉ dùng sentinel giả.
- OpenAPI mặc định phản hồi khi chưa đăng nhập. Không thấy limiter login
  trong source app. Cần xác minh chính sách docs, rate limit, HTTPS cookie và
  thu hồi phiên tại môi trường triển khai. [Chi tiết bảo mật](BUG_REPORT.md)

## Phép đo hiệu năng synthetic

Một tiến trình benchmark, một worker, SQLite tạm, spool có sẵn và adapter
đích in-memory. Dataset link-state có 10% replay. Bảng ghi CPU theo phần trăm
một core và RSS lấy mẫu cuối công đoạn. Latency đo mỗi lần xử lý record với
spool đã sẵn, gồm checkpoint và adapter fake.

| Input duy nhất | Parse record/s | Correlate record/s | Worker record/s gồm replay | Worker p95 | CPU worker | RSS worker cuối |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 14.089,87 | 122,66 | 59,80 | 18,315 ms | 51,8% | 57,5 MiB |
| 1.000 | 21.356,66 | 112,60 | 51,26 | 25,382 ms | 48,3% | 57,2 MiB |

Worker gọi mỗi adapter 110/1.100 lần cho hai tải tương ứng. ID distinct và
tổng count aggregate giữ đúng 100/1.000. Replay vẫn dùng downstream write
attempts. Test native riêng xác nhận upsert và retry có tính idempotent.

Với Down lặp trên **một OSPF adjacency**, correlation giảm từ **94,77** xuống
**57,06 record/s** khi tăng từ 100 lên 1.000 observation; p95 tăng từ
**12,078** lên **27,418 ms**. RSS cuối công đoạn tăng từ 52,2 lên 59,4 MiB.
Kết quả phù hợp với việc dựng lại projection theo lịch sử adjacency mỗi lần
ghi. Cần đo soak test và backlog trên dữ liệu lab trước khi đặt SLO.

Benchmark có giới hạn kích thước và timeout ngoài tiến trình. Số đo áp dụng
cho một lượt chạy trên Windows với storage đích fake. Chúng không bao gồm
độ trễ TCP/UDP, PostgreSQL/Loki qua mạng, Grafana, Telegram hay Ubuntu.
Chặng pipeline **10.000 event** chạm giới hạn toàn tiến trình **100 giây**
trước khi trả số đo hoàn chỉnh. Tiến trình test đã dừng, thư mục tạm được giữ
cho đối soát. Lượt parse-only riêng xử lý đủ **10.000 ID duy nhất trong 0,4524 giây**
(**22.104,28 record/s**, CPU 96,7% của một core, RSS cuối 37,1 MiB). Không có số
đo correlation, độ trễ worker hoặc storage đủ 10.000 event.
[Harness](../../tests/qa_benchmark.py)

## Skipped, giới hạn và các bước nghiệm thu còn lại

1. `test_rsyslog_collection.py` và `test_processor_pipeline.py` phụ thuộc
   Docker daemon. Compose CLI sẵn có, Linux engine pipe không tồn tại trong
   phiên QA. Kiểm tra socket TCP/UDP, quyền volume thực tế và restart stack
   bằng deployment cô lập trên Ubuntu.
2. Provision Grafana thật rồi kiểm tra datasource, renderer, macro và chọn
   time range rỗng/có dữ liệu. Truy vấn Loki đã chạy với macro thay thế.
3. Nghiệm thu GNS3 R1 CHR ↔ R2 IOSv Area 0, kiểm tra đường đi Syslog khi transit
   ngắt, lấy mẫu Down/Full đã khử dữ liệu và map hai endpoint thật. Snapshot
   GNS3 được đọc bởi test repo vẫn là snapshot cũ.
4. Thử một vòng Down → ACK → Full → Resolve trên lab, replay và restart,
   đo backlog/latency/RAM. Kiểm tra thêm HTTPS, proxy và delivery Telegram
   thực sau khi được phép.

## Tệp của chiến dịch

- Báo cáo này, `docs/qa/TEST_MATRIX.md` và `docs/qa/BUG_REPORT.md`.
- Dataset và công cụ QA mới `tests/qa_synthetic.py`, `tests/test_qa_syslog.py`,
  `tests/qa_benchmark.py`.
- Mở rộng `tests/test_storage_api.py`, `tests/test_storage_loki.py`,
  `tests/test_processor.py`, `tests/test_ospf_notifications.py`,
  `tests/test_e2e_playwright.py`,
  `tests/integration/test_postgres_ospf_lifecycle.py` và
  `tests/integration/test_ospf_loki_queries.py`.

## Cổng chất lượng tại mốc QA ban đầu

Mốc ban đầu được đánh giá **FAIL** do QA-05 và QA-01. Kết quả sau khi xử lý
hai lỗi và chạy lại native nằm trong [mốc hồi quy tương ứng](#mốc-hồi-quy-sau-bản-sửa-qa-01-và-qa-05).
