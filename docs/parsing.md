# Phase 3 — Multi-Vendor Parsing and Normalization

## Contract

`app.schemas.event.NormalizedEvent` là contract Pydantic bất biến, `extra="forbid"`, phiên bản `schema_version: "1.0"`. Contract này tách khỏi `Alert 1.0`: event mô tả một syslog record đã parse; alert là detection/lifecycle state cho dashboard.

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

## Coverage đã xác minh

| Vendor/product | Vendor identifier | Event type | Fixture | Trạng thái |
|---|---|---|---|---|
| Cisco IOS | `LINK-3-UPDOWN` | `link_up`, `link_down` | `cisco-ios.log` có `down` | Parse; `up` dùng cùng documented message shape nhưng chưa có regression fixture |
| Cisco IOS | `SYS-5-CONFIG_I` | `configuration_change` | `cisco-ios.log` | Parse đúng sample `user on vty (IP)` |
| Cisco IOS | `PORT_SECURITY-2-PSECURE_VIOLATION` | `port_security` | `cisco-ios.log` | Parse MAC và interface |
| MikroTik RouterOS | topics + `login failure for user` | `login_failure` | `mikrotik.log` | Parse SSH/Winbox, user, source IP, topic severity |
| pfSense filterlog | IPv4 `block` | `acl_deny` | `pfsense-opnsense.log` | Parse documented CSV fields, TCP addresses/ports/rule/interface |

Pattern Cisco được đối chiếu với [Cisco system message examples](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/15-0_2_se/system/message/smg3750/overview.html) và [PORT_SECURITY message guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/cisco_ie2000/software/release/15_0_2_ea/system/messages/System_message/msg_desc.html). MikroTik topic và login wording được đối chiếu với [RouterOS logging documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log) và ví dụ chính thức [Syslog with Elasticsearch](https://help.mikrotik.com/docs/spaces/ROS/pages/282132697/Syslog%2Bwith%2BElasticsearch). Vị trí field pfSense dựa trên [Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html).

## Unsupported hoặc chưa xác minh

- Port Flap: chưa có raw sample thể hiện nhiều transition/cửa sổ thời gian. Parser chỉ tạo từng `link_up`/`link_down`; correlation/flap detection chưa được suy đoán.
- Routing Neighbor Down: không có BGP/OSPF neighbor-down sample trong repository.
- Cisco `SEC_LOGIN-5-LOGIN_SUCCESS` và `SYS-5-RESTART`: có fixture nhưng ngoài event types Phase 3, trả `unknown`.
- Cisco format có prefix `*`, timezone token, stack suffix, multiline hoặc cấu hình qua TFTP chưa được hỗ trợ dù một số biến thể xuất hiện trong tài liệu.
- OPNsense `arpwatch` và OpenVPN samples: chưa có mapping cho event types được yêu cầu, trả `unknown`.
- OPNsense `filterlog`, pfSense IPv6/ICMP, pass records và alternate syslog/RFC 5424 envelope: chưa có fixture regression, không công bố hỗ trợ.
- Open vSwitch unknown-VLAN sample: chưa có event type tương ứng, trả `unknown`.
- MikroTik format không có year hoặc có remote RFC 3164 envelope chưa được hỗ trợ.

## Timestamp assumptions

Cisco và pfSense samples thiếu year/timezone. Parser nhận `received_at` và `source_timezone`, chọn year gần receipt time nhất rồi chuyển UTC. Mặc định timezone là UTC; production processor phải truyền timezone của thiết bị. MikroTik fixture có year nhưng vẫn không có timezone nên dùng cùng `source_timezone`.

## Failure semantics

`parse_syslog()` không ném exception do payload:

- `parsed`: có `NormalizedEvent` hợp lệ.
- `unknown`: format/event hợp lệ nhưng chưa có parser đã xác minh.
- `malformed`: vendor lookalike không hoàn chỉnh, IP/port/timestamp không hợp lệ, delimiter nguy hiểm hoặc quá kích thước.

Result luôn giữ raw input để điều tra; reason dùng code cố định thay vì đưa exception hoặc raw payload vào log. Unknown/malformed event không được tự gán vendor/event type và không trở thành alert.

## Kiểm thử fixture

```bash
python -m pytest tests/test_multi_vendor_parsers.py
```

Tests đọc trực tiếp bốn file dưới `fixtures/logs`, xác minh field normalization, raw preservation, UTC conversion, stable event ID, strict schema, unknown formats và malformed input.
