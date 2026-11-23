# Phase 3 — Multi-Vendor Parsing and Normalization

## Contract

`app.schemas.event.NormalizedEvent` là contract Pydantic bất biến, `extra="forbid"`, đọc được `schema_version` `1.0` và `1.1`. Event mô tả một bản ghi syslog đã parse. `Alert 1.0` mô tả cảnh báo và vòng đời trên dashboard.

Các nhóm field chính:

- Identity: `schema_version`, SHA-256 `event_id`, `parser_name`, `parser_version`.
- Time: `timestamp`, `received_at`; bắt buộc timezone-aware và lưu UTC.
- Classification: `vendor`, `product`, `event_type`, `severity`, `outcome`.
- Network/device: device, interface/state, source/destination IP/port, protocol, direction.
- Actor/action: username, auth method, session, MAC, action, vendor rule/severity.
- Evidence: `message` đã tách và `raw_message` nguyên văn.

Raw message của event parse thành công phải giống input từng ký tự. Parser từ chối record rỗng, record chứa CR/LF/NUL và input lớn hơn 32 KiB trước khi chạy regex. Bản gốc vượt giới hạn vẫn nằm trong raw spool Phase 2; parse result chỉ báo `message_too_large` và không tạo normalized event.

Versioning:

- Patch: sửa parser/validation nhưng không đổi wire contract.
- Minor: chỉ thêm field optional/default và consumer cũ phải tiếp tục hoạt động.
- Major: đổi/xóa/đổi nghĩa field; cần chạy song song contract cũ và mới khi migration.

Event hiện hữu tiếp tục dùng `1.0` với cùng field, giá trị null và công thức `event_id`. Event OSPF mới dùng `1.1` vì parser strict cũ sẽ từ chối field và enum mới. Loki ghi cả hai phiên bản vào stream mang label `schema_version` tương ứng. Reader mới đọc cả hai, dữ liệu lịch sử giữ nguyên. API chỉ trả `1.0` theo mặc định, với [opt-in để đọc OSPF](api.md#get-apiv1events).

Khi nâng phiên bản, đưa dashboard/API và các consumer cần đọc OSPF lên bản có reader `1.1` trước khi cập nhật processor. Reader cũ bỏ qua event `1.1`. SHA-256 vẫn tính trên phiên bản schema, vendor, parser, device, timestamp sự kiện và raw input. Replay cùng input, nguồn và timestamp giữ nguyên ID. Dạng có PRI và dạng đã bỏ PRI là hai chuỗi input khác nhau. Worker tiếp tục giữ bản gốc ở spool và đưa `parse_message` vào parser.

## Coverage đã xác minh

| Vendor/product | Vendor identifier | Event type | Fixture | Trạng thái |
|---|---|---|---|---|
| Cisco IOS | `LINK-3-UPDOWN` | `link_up`, `link_down` | `cisco-ios.log` có `down` | Parse; `up` dùng cùng documented message shape nhưng chưa có regression fixture |
| Cisco IOS | `SYS-5-CONFIG_I` | `configuration_change` | `cisco-ios.log` | Parse đúng sample `user on vty (IP)` |
| Cisco IOS | `PORT_SECURITY-2-PSECURE_VIOLATION` | `port_security` | `cisco-ios.log` | Parse MAC và interface |
| MikroTik RouterOS | topics + `login failure for user` | `login_failure` | `mikrotik.log` | Parse SSH/Winbox, user, source IP, topic severity |
| pfSense filterlog | IPv4 `block` | `acl_deny` | `pfsense-opnsense.log` | Parse documented CSV fields, TCP addresses/ports/rule/interface |

Pattern Cisco được đối chiếu với [Cisco system message examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/15-0_2_se/system/message/smg3750/overview.html) và [PORT_SECURITY message guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/cisco_ie2000/software/release/15_0_2_ea/system/messages/System_message/msg_desc.html). MikroTik topic và login wording được đối chiếu với [RouterOS logging documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log) và ví dụ chính thức [Syslog with Elasticsearch](https://help.mikrotik.com/docs/spaces/ROS/pages/282132697/Syslog%2Bwith%2BElasticsearch). Vị trí field pfSense dựa trên [Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html).

## OSPFv2 Phase 1

Các fixture `cisco-ospf-synthetic.log`, `mikrotik-ospf-synthetic.log` và
`mikrotik-ospf-dual-synthetic.log` là dữ liệu mô phỏng dựa trên mẫu công khai, dùng
địa chỉ dành cho tài liệu. Fixture dual kiểm tra local/peer ID đảo chiều, Down, Full
và trạng thái trung gian từ hai CHR. Các fixture ban đầu tiếp tục kiểm tra Cisco,
RouterOS BSD remote và console. Các mẫu remote thật từ cả R1 và R2 vẫn cần thu thập.

| Nguồn | Dạng được kiểm thử | Metadata có trong log |
|---|---|---|
| Cisco IOS | `%OSPF-5-ADJCHG` với `Process …, Nbr … on … from … to …, …`. Timestamp theo header IOS hiện có, có thể kèm `*`, số thứ tự và PRI. | `Nbr` là router ID của peer. `interface_name` lấy từ `on`. Process ID không biểu thị Area ID. [Cisco Down và Full](https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13697-25.pdf) · [Cisco intermediate states](https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Campus/VSS30dg/campusVSS_DG/VSS-dg_ch3.pdf) · [Ví dụ remote IOS](https://community.cisco.com/t5/other-collaboration-subjects/need-more-detail-on-cme-cdr/td-p/357068) |
| MikroTik RouterOS v7 | Payload có `version: 2`, area, `interface { … IPv4%interface }` và `neighbor { router-id: … state: … } state change to …`. Hỗ trợ console có ngày/năm và remote BSD hoặc ISO 8601 có timezone, có hoặc không có topics. Khi có topics, cần `ospf`. | Area ID, router ID local/peer và tên interface sau `%`. IPv4 trước `%` là địa chỉ interface local. [RouterOS v7 log công khai](https://forum.mikrotik.com/t/ospf-not-installing-connected-routes/176643/3) · [RouterOS wire format](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/) |

`NormalizedEvent 1.1` dùng `routing_protocol="ospf"`, `previous_state`, `current_state` và `neighbor_router_id`. Khi log cung cấp, parser thêm `ospf_area`, `local_router_id` và dùng lại `interface_name`. Các địa chỉ và ID OSPF dùng IPv4 dạng dotted quad. `neighbor_ip` dành cho địa chỉ peer được cung cấp rõ ràng. Hai dạng log trên chưa có trường này. Metadata OSPF thiếu được lược khỏi JSON. `source_ip` và `interface_state` giữ nguyên ngữ nghĩa.

| Trạng thái đích | Event type | Outcome |
|---|---|---|
| `DOWN` | `routing_neighbor_down` | `failure` |
| `FULL` | `routing_neighbor_up` | `success` |
| `ATTEMPT`, `INIT`, `2-WAY`, `EXSTART`, `EXCHANGE`, `LOADING` | `routing_neighbor_state_change` | `unknown` |

`2WAY` và `TwoWay` được chuẩn hóa thành `2-WAY`. `FULL` xác nhận trạng thái adjacency từ bản ghi đó. Việc ghép nó với lần Down trước đó thuộc correlation. Severity Cisco giữ mapping từ syslog level. RouterOS dùng severity topic nếu có, hoặc `low` nếu thiếu. [OSPF neighbor states](https://www.rfc-editor.org/rfc/rfc2328.html#section-10.1)

## Unsupported hoặc chưa xác minh

- Port Flap: chưa có raw sample thể hiện nhiều transition/cửa sổ thời gian. Parser chỉ tạo từng `link_up`/`link_down`; correlation/flap detection chưa được suy đoán.
- BGP, OSPFv3 và format OSPF ngoài các mẫu trên chưa được hỗ trợ. Cần mẫu live từ cả
  hai CHR để xác minh header, timezone, topics/prefix, Down, Full và trạng thái trung
  gian nếu thiết bị phát.
- Cisco IOS parser nhận interface Link Up/Down, config và port security theo đúng
  định dạng fixture. Các fixture này chưa xác minh image IOSvL2 của lab. Cần mẫu
  syslog từ image được chọn vì header và payload phát qua mạng có thể khác mẫu IOS.
- Cisco `SEC_LOGIN-5-LOGIN_SUCCESS` và `SYS-5-RESTART`: có fixture nhưng ngoài event types Phase 3, trả `unknown`.
- Cisco `*` hoặc số thứ tự được nhận cho `OSPF-5-ADJCHG`. Timezone token, stack suffix, multiline, record thiếu ngày/tháng và cấu hình qua TFTP chưa được hỗ trợ.
- OPNsense `arpwatch` và OpenVPN samples: chưa có mapping cho event types được yêu cầu, trả `unknown`.
- OPNsense `filterlog`, pfSense IPv6/ICMP, pass records và alternate syslog/RFC 5424 envelope: chưa có fixture regression, không công bố hỗ trợ.
- Open vSwitch unknown-VLAN sample: chưa có event type tương ứng, trả `unknown`.
- Định dạng remote RouterOS chỉ áp dụng cho OSPFv2. Login failure giữ format console cũ. Dạng OSPF console chỉ có giờ, action prefix tùy biến, CEF và message kiểu RouterOS v6 chưa được hỗ trợ.

## Timestamp assumptions

Cisco, pfSense và RouterOS BSD remote thiếu year/timezone. Parser dùng `source_timezone`, chọn năm gần `received_at` nhất rồi chuyển UTC. RouterOS console có năm và dùng `source_timezone`. RouterOS ISO 8601 có offset tường minh nên dùng offset từ bản ghi.

## Failure semantics

`parse_syslog()` không ném exception do payload:

- `parsed`: có `NormalizedEvent` hợp lệ.
- `unknown`: format/event hợp lệ nhưng chưa có parser đã xác minh.
- `malformed`: vendor lookalike không hoàn chỉnh, IP/port/timestamp không hợp lệ, delimiter nguy hiểm hoặc quá kích thước.

Result luôn giữ raw input để điều tra; reason dùng code cố định thay vì đưa exception hoặc raw payload vào log. Unknown/malformed event không được tự gán vendor/event type và không trở thành alert.

## Kiểm thử fixture

```bash
python -m pytest tests/test_multi_vendor_parsers.py tests/test_ospf_parsers.py
```

Tests đọc trực tiếp các fixture dưới `fixtures/logs` để kiểm tra chuẩn hóa, giữ nguyên raw input, UTC, replay ID, schema strict, unknown và malformed. Test worker, Loki và API kiểm tra đường đi của hai phiên bản bằng backend giả lập.
