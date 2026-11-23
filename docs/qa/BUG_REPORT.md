# NetworkSec N4.2 · Lỗi xác nhận và rủi ro cần kiểm tra

Sáu lỗi được tái hiện ở base Git `df18567` cùng các thay đổi OSPF đang có trong
working tree. Lần chạy `--runxfail` cho **7 lỗi kiểm thử tái hiện** vì QA-01 có
cả bài mock và bài trên Loki thật. Các test hồi quy đánh dấu `xfail(strict=True)`
để lần sửa đúng tạo XPASS và yêu cầu bỏ marker. Các bước bên dưới dùng dữ liệu
synthetic trên localhost hoặc adapter fake.

## Trạng thái sau hồi quy ngày 23/11/2026

Sáu lỗi đã được sửa và kiểm thử trong cùng working tree. Lượt xử lý cuối chạy bốn
bài tái hiện nguyên bản với `--runxfail` trước và sau khi sửa. Kết quả chuyển từ
**4 failed** sang **4 passed**. Bốn marker được gỡ sau lượt đạt.
Chi tiết theo severity bên dưới giữ bằng chứng lần phát hiện đầu.

| ID | Severity · ưu tiên | Trạng thái và bằng chứng hiện hành |
|---|---|---|
| QA-01 | High · P1 | **Đã sửa**. Mock và Loki 3.7.0 trả cursor và đọc được trang sau khi replay chiếm slot. Test thêm có 760 event cùng timestamp, cursor cũ và stream trộn schema. [Mock](../../tests/test_storage_loki.py#L266), [Loki thật](../../tests/integration/test_ospf_loki_queries.py#L98). |
| QA-02 | Low · P3 | **Đã sửa**. Chuỗi CSRF Unicode không hợp lệ và token bị thiếu ở các request còn lại hợp lệ trả 403. Token ASCII hợp lệ vẫn dùng `compare_digest`. [Validator](../../app/web/auth.py#L49), [test](../../tests/test_storage_api.py). |
| QA-03 | Medium · P2 | **Đã sửa**. Envelope hoặc stream sai kiểu trở thành lỗi protocol và API event trả HTTP 502 với thông báo chung. Kết quả rỗng hợp lệ, schema 1.0/1.1 và replay cursor vẫn qua test. [Adapter](../../app/storage/loki.py#L136), [test](../../tests/test_storage_loki.py). |
| QA-04 | Medium · P2 | **Đã sửa**. Parser exception đánh dấu `blocked` ngay. Retry, restart và heartbeat không xóa block. Xử lý thành công hoặc đưa input được xác định lỗi vào DLQ có thể khôi phục. Reconciliation idle thành công chỉ xóa block thuộc chính reconciliation. [Worker](../../app/processor/worker.py#L88), [health store](../../app/processor/state.py#L263). |
| QA-05 | High · P1 | **Đã sửa**. PostgreSQL 17.7 xác nhận ACK/Resolve theo cả hai thứ tự khóa. ACK muộn sau Resolve thủ công và sau Full tự động trả bản ghi đã đóng, giữ note, actor và history. [Khóa hàng](../../app/storage/postgres.py#L582), [test](../../tests/integration/test_postgres_ospf_lifecycle.py#L925). |
| QA-06 | Low · P2 | **Đã sửa**. HTTP 422 giữ `loc`, `type` và thông báo an toàn cho từng lỗi; bỏ input và context. Test mật khẩu quá dài, secret lồng, JSON sai và log không thấy giá trị synthetic. [Handler](../../app/main.py#L83), [test](../../tests/test_storage_api.py). |

Sáu phát hiện đã được đóng trong phạm vi kiểm thử phần mềm. Nghiệm thu runtime Compose
và Ubuntu/GNS3 vẫn thiếu bằng chứng. Xem [báo cáo hồi quy](FULL_MOCK_QA_REPORT.md).

## High

### QA-01 · Loki báo hết trang khi một bản replay chiếm slot

- **Thành phần** · API danh sách event, trang Events và adapter Loki.
- **Tái hiện** · Dùng ba event ID khác nhau trong Loki cô lập. Ghi event mới nhất
  lần thứ hai với cùng timestamp và ID, thay `received_at` để mô phỏng một lần
  thu nhận khác. Đọc theo thiết bị với limit 2. Bài mock trả đúng ba record đầu
  từ upstream. Bài native thực hiện push và query thật.
- **Kỳ vọng** · Trả hai event mới nhất và cursor cho event còn lại.
- **Trước bản sửa** · `next_cursor=None`. Query cùng khoảng với limit 10 trả đủ ba ID.
  ID thứ ba vẫn có trong Loki nhưng client không nhận được đường sang trang đó.
- **Nguyên nhân** · `fetch_limit = limit + len(seen_ids) + 1`. Các dòng lặp bị
  bỏ trước khi xét `has_more`. Adapter không lấy tiếp khi upstream đã chạm limit
  còn danh sách distinct vừa đủ một trang.
- **Sửa đề xuất** · Bổ sung tiến trình đọc phân trang theo vị trí upstream, với
  giới hạn tìm kiếm hữu hạn. Chỉ báo hết trang khi có bằng chứng upstream đã
  cạn. Kiểm tra các trường hợp trùng nhiều dòng cùng timestamp và payload lỗi.
- **Regression** · Giữ cả bài mock lẫn native, rồi kiểm tra thêm việc đi hết các
  trang với đúng tập ID và không lặp. [Adapter Loki](../../app/storage/loki.py#L59),
  [mock](../../tests/test_storage_loki.py#L265),
  [native](../../tests/integration/test_ospf_loki_queries.py#L99).

### QA-05 · ACK từ màn hình cũ mở lại incident đã Resolve

- **Thành phần** · Vòng đời operational alert, API ACK và PostgreSQL.
- **Tái hiện** · Trên PostgreSQL tạm đã migrate, mở OSPF incident, Resolve với
  một actor, rồi gửi ACK từ actor khác như khi màn hình cũ còn mở.
- **Kỳ vọng** · Resolve và note giữ nguyên. Thay đổi trạng thái sau Resolve cần
  thao tác đổi trạng thái chủ ý. ACK muộn có thể là no-op hoặc trả conflict
  theo hợp đồng API đã chọn.
- **Trước bản sửa** · Trạng thái đọc lại là `acknowledged`, dù trước đó là `resolved`.
  Luồng cập nhật cũng cho phép ghi đè note. Bài hai request đồng thời riêng
  xác nhận PostgreSQL ghi history thành chuỗi nhất quán, song trạng thái cuối
  phụ thuộc thứ tự hai thao tác.
- **Nguyên nhân** · `acknowledge()` gọi `update_status()` chung. Câu UPDATE dùng
  `status = requested.status` mà thiếu điều kiện trạng thái hiện thời cho ACK.
- **Sửa đề xuất** · Ràng buộc transition ACK nguyên tử tại PostgreSQL và quy
  định rõ trả kết quả lặp hoặc xung đột. Giữ đường đổi trạng thái chủ ý riêng.
- **Regression** · Kiểm tra ACK sau Resolve thủ công và tự động, hai thứ tự
  ACK/Resolve, lịch sử và note. [PostgreSQL](../../app/storage/postgres.py#L579),
  [API ACK](../../app/web/api.py#L189),
  [test native](../../tests/integration/test_postgres_ospf_lifecycle.py#L900).

## Medium

### QA-03 · Response JSON sai shape từ Loki thoát ra ngoài lớp lỗi storage

- **Thành phần** · Adapter Loki và hợp đồng lỗi Events API.
- **Tái hiện** · Cho `httpx.MockTransport` trả HTTP 200 cùng JSON array, sau đó
  gọi `query_events()`.
- **Kỳ vọng** · Adapter ném `StorageError` để API áp dụng nhánh HTTP 502.
- **Trước bản sửa** · `AttributeError: 'list' object has no attribute 'get'` thoát
  adapter. Lượt hồi quy riêng với transport mock xác nhận HTTP 500 qua endpoint.
- **Nguyên nhân** · `document.get()` được gọi trước khi xác nhận kiểu JSON.
  Handler chỉ quy đổi các nhóm lỗi khác sang `StorageError`.
- **Sửa đề xuất** · Kiểm tra envelope là object và xác thực các trường bắt buộc
  trước khi đọc nội dung. Giữ lỗi 502 ổn định và tránh trả backend payload.
- **Regression** · Parametrize array, null, scalar và object thiếu `data.result`
  qua adapter và API. [Adapter Loki](../../app/storage/loki.py#L74),
  [mapping API](../../app/web/api.py#L89), [test](../../tests/test_storage_loki.py#L252).

### QA-04 · Lỗi parser bất ngờ giữ health ở trạng thái healthy

- **Thành phần** · Processor, health state và checkpoint.
- **Tái hiện** · Ghi hai envelope synthetic. Xử lý record đầu, tiêm
  `RuntimeError` ở parser của record thứ hai rồi đọc health. Gỡ fault và
  dựng worker mới trên SQLite tạm cũ.
- **Kỳ vọng** · Checkpoint giữ nguyên, health chuyển `blocked` ngay. Sau khi gỡ
  fault, worker xử lý lại record thứ hai đúng một lần về mặt event ID.
- **Trước bản sửa** · Health vẫn `healthy`, `processed_count=1`. Hai event được ghi
  sau restart. Healthcheck chỉ báo lỗi muộn khi heartbeat cũ hết hạn nếu fault
  còn tiếp diễn. Thử nghiệm này không quan sát mất hoặc tăng trùng event.
- **Nguyên nhân** · Bước `parse_syslog()` nằm ngoài vùng đánh dấu `blocked`.
  Retry loop bắt lỗi và giữ offset, còn health chưa được cập nhật.
- **Sửa đề xuất** · Đánh dấu blocked với lý do đã khử dữ liệu cho lỗi parser
  bất ngờ. Duy trì retry, giữ evidence và không tự skip record chưa xác định.
- **Regression** · Thử fault lặp, healthcheck ngay sau lỗi và hồi phục sau
  restart. [Worker](../../app/processor/worker.py#L111),
  [healthcheck](../../app/processor/healthcheck.py#L11),
  [test](../../tests/test_processor.py#L450).

## Low

### QA-02 · CSRF không hợp lệ chứa Unicode trả 500

- **Thành phần** · Validator CSRF chung cho form và API session.
- **Tái hiện** · Khởi tạo một phiên login chưa xác thực trong TestClient,
  gửi form login với giá trị CSRF chứa ký tự Unicode và credential synthetic.
- **Kỳ vọng** · HTTP 403 theo hợp đồng invalid CSRF.
- **Trước bản sửa** · HTTP 500. Không thấy thao tác hoặc xác thực được chấp nhận.
- **Nguyên nhân** · `hmac.compare_digest()` nhận hai chuỗi, yêu cầu ASCII và
  ném lỗi cho chuỗi chứa Unicode trong nhánh này.
- **Sửa đề xuất** · Kiểm tra định dạng hoặc so sánh byte theo một encoding
  xác định, quy đổi input sai về 403 và giữ so sánh constant-time.
- **Regression** · Kiểm tra form Unicode, sai ASCII, thiếu và token đúng, cùng
  mutating API. [Validator](../../app/web/auth.py#L49),
  [login](../../app/web/routes.py#L193), [test](../../tests/test_storage_api.py#L502).

### QA-06 · Login 422 phản chiếu trường mật khẩu

- **Thành phần** · Validation lỗi form FastAPI.
- **Tái hiện** · Gửi form login với phiên test, CSRF hợp lệ và mật khẩu
  synthetic dài quá 1.024 ký tự.
- **Kỳ vọng** · HTTP 422 chỉ trả tên trường và thông tin lỗi cần sửa.
- **Trước bản sửa** · HTTP 422 chứa giá trị đã gửi trong `detail[].input`. Bài test
  thấy marker synthetic trong response gửi về chính caller. Chưa quan sát
  log production hay dữ liệu của người dùng khác.
- **Nguyên nhân** · Giới hạn của `Form` được FastAPI kiểm tra trước handler.
  App dùng handler validation mặc định, trả giá trị đầu vào ở lỗi.
- **Sửa đề xuất** · Khử trường nhạy cảm khỏi validation response và telemetry.
  Giữ mã 422 và metadata đủ chẩn đoán.
- **Regression** · Test field nhạy cảm quá dài và thiếu field. Kiểm tra response
  và log với sentinel giả. [Khai báo form](../../app/web/routes.py#L193),
  [khởi tạo middleware](../../app/main.py#L72), [test](../../tests/test_storage_api.py#L523).

## Rủi ro chưa được xác nhận thành lỗi

| Hạng mục | Bằng chứng hiện có | Kiểm tra còn thiếu |
|---|---|---|
| Bề mặt OpenAPI | Test không cần phiên truy cập được docs mặc định. Factory FastAPI không điều kiện hóa docs theo `APP_ENV`. Cấu hình Compose publish Dashboard trên loopback. | Chốt yêu cầu exposure khi có reverse proxy và policy production. [Factory](../../app/main.py#L72) |
| Rate limiting login và thu hồi cookie | Không thấy limiter login hoặc store thu hồi server-side trong router/middleware. Test xác nhận cookie lỗi bị từ chối, cookie phiên được đổi sau login và logout chặn phiên trình duyệt hiện tại. | Xác thực rate limit tại proxy và chính sách thu hồi trên Ubuntu. [Routes](../../app/web/routes.py#L193), [session](../../app/main.py#L74) |
| Cảnh báo Telegram lần đầu mơ hồ | Fake xác nhận trạng thái `uncertain` sau timeout và không tự gửi lần nữa. | Vận hành cần đối soát delivery thật và hành vi proxy. [Worker Telegram](../../app/bot/ospf.py#L74) |
| OSPF journal dài và dữ liệu cũ | Projection đọc và fold lại lịch sử cùng adjacency mỗi lần. Loki và spool có giới hạn riêng. | Đo soak test Ubuntu, disk retention và backlog, đặc biệt khi nhiều cửa sổ outage hoặc topology lớn. [Correlation store](../../app/services/correlation.py#L352) |
| Kết nối Syslog/R1–R2 | Cấu hình mặc định giữ bind loopback, `ospf.links: []`. Test hiện có chỉ đọc snapshot GNS3 lịch sử và backend nhận envelope mô phỏng. | Lấy mẫu hai đầu, chốt mapping, xác nhận đường quản trị và thử TCP/UDP thật trên lab. [Rules](../../config/correlation_rules.yaml#L19) |

Các rủi ro trong bảng này vẫn cần bằng chứng riêng khi kiểm thử môi trường đích.
