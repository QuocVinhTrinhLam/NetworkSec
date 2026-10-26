# Rules Catalog

Generated from `config/rules_catalog.yaml`. Edit the YAML, then rerun `python scripts/generate_rules_catalog.py`.

## Port scan (`port-scan`)

Detects one source probing multiple ports or services in a short interval.

- Default severity: **high**
- Rule IDs: `100201`
- Groups: `port_scan`, `network_scan`
- MITRE ATT&CK: `T1046` Network Service Discovery (Discovery)
- Recommended (EN): Block or rate-limit the source IP and verify exposed services.
- Khuyến nghị (VI): Chặn hoặc giới hạn tốc độ IP nguồn và kiểm tra các dịch vụ đang công khai.

## SSH, Telnet or Winbox brute force (`network-brute-force`)

Detects repeated authentication failures against network-management services.

- Default severity: **critical**
- Rule IDs: `100210`, `100211`, `100212`
- Groups: `brute_force`, `ssh_brute_force`, `telnet_brute_force`, `winbox_brute_force`
- MITRE ATT&CK: `T1110` Brute Force (Credential Access)
- Recommended (EN): Block the source IP, review authentication logs and rotate exposed credentials.
- Khuyến nghị (VI): Chặn IP nguồn, rà soát nhật ký xác thực và thay đổi thông tin đăng nhập có nguy cơ lộ.

## Administrative login succeeded (`admin-login-success`)

Detects a successful administrative login to a managed network device.

- Default severity: **medium**
- Rule IDs: `100220`
- Groups: `admin_login_success`, `authentication_success`
- MITRE ATT&CK: `T1078` Valid Accounts (Defense Evasion)
- Recommended (EN): Confirm the login against the approved change window and investigate unexpected accounts or sources.
- Khuyến nghị (VI): Đối chiếu lần đăng nhập với lịch thay đổi đã duyệt và điều tra tài khoản hoặc nguồn bất thường.

## Administrative login failed (`admin-login-failure`)

Detects a failed administrative login to a managed network device.

- Default severity: **high**
- Rule IDs: `100221`
- Groups: `admin_login_failed`, `authentication_failed`
- MITRE ATT&CK: `T1110` Brute Force (Credential Access)
- Recommended (EN): Validate the source, check for repeated attempts and lock or reset the account when appropriate.
- Khuyến nghị (VI): Xác minh nguồn, kiểm tra các lần thử lặp lại và khóa hoặc đặt lại tài khoản khi cần thiết.

## Network device configuration change (`configuration-change`)

Detects an administrative change to a router, switch or firewall configuration.

- Default severity: **high**
- Rule IDs: `100230`
- Groups: `config_changed`, `configuration_change`
- MITRE ATT&CK: `T1562.001` Impair Defenses - Disable or Modify Tools (Defense Evasion)
- Recommended (EN): Compare the running configuration with the approved baseline and identify the operator.
- Khuyến nghị (VI): So sánh cấu hình đang chạy với bản chuẩn đã duyệt và xác định người thực hiện thay đổi.

## Interface flapping (`interface-flapping`)

Detects repeated interface up/down transitions that may indicate a fault or network loop.

- Default severity: **medium**
- Rule IDs: `100240`
- Groups: `interface_flap`, `interface_state`
- MITRE ATT&CK: `T1498` Network Denial of Service (Impact)
- Recommended (EN): Check the cable, peer device and interface counters, then isolate a possible loop.
- Khuyến nghị (VI): Kiểm tra cáp, thiết bị đầu bên kia và bộ đếm cổng, sau đó cô lập vòng lặp mạng nếu có.

## ARP spoofing (`arp-spoofing`)

Detects conflicting ARP bindings or behavior consistent with ARP cache poisoning.

- Default severity: **critical**
- Rule IDs: `100251`
- Groups: `arp_spoofing`, `arp_poisoning`
- MITRE ATT&CK: `T1557.002` Adversary-in-the-Middle - ARP Cache Poisoning (Credential Access)
- Recommended (EN): Quarantine the source host, verify ARP bindings and inspect affected endpoints for interception.
- Khuyến nghị (VI): Cách ly máy nguồn, xác minh bảng ánh xạ ARP và kiểm tra các máy bị ảnh hưởng để tìm dấu hiệu nghe lén.

## MAC flooding or port-security violation (`mac-flooding-port-security`)

Detects excessive MAC learning or a switch port-security violation.

- Default severity: **critical**
- Rule IDs: `100250`, `100252`
- Groups: `mac_flooding`, `port_security`
- MITRE ATT&CK: `T1498` Network Denial of Service (Impact)
- Recommended (EN): Disable or quarantine the affected access port and inspect the connected source host.
- Khuyến nghị (VI): Tắt hoặc cách ly cổng access bị ảnh hưởng và kiểm tra máy nguồn đang kết nối.

## VLAN hopping (`vlan-hopping`)

Detects double-tagged frames or unauthorized trunk negotiation on an access port.

- Default severity: **critical**
- Rule IDs: `100260`
- Groups: `vlan_hopping`, `double_tagging`
- MITRE ATT&CK: `T1595.002` Active Scanning - Vulnerability Scanning (Reconnaissance)
- Recommended (EN): Quarantine the port and verify access mode, native VLAN and trunk negotiation settings.
- Khuyến nghị (VI): Cách ly cổng và kiểm tra chế độ access, native VLAN cùng cấu hình thương lượng trunk.

## SYN flood or denial of service (`syn-flood`)

Detects a TCP SYN rate that exceeds the configured denial-of-service threshold.

- Default severity: **critical**
- Rule IDs: `100270`
- Groups: `syn_flood`, `dos`
- MITRE ATT&CK: `T1498.001` Network Denial of Service - Direct Network Flood (Impact)
- Recommended (EN): Enable SYN protection or rate limiting, block abusive sources and preserve traffic evidence.
- Khuyến nghị (VI): Bật bảo vệ SYN hoặc giới hạn tốc độ, chặn nguồn tấn công và lưu giữ bằng chứng lưu lượng.

## VPN login anomaly (`vpn-anomaly`)

Detects a VPN login from an unusual source, location or account context.

- Default severity: **high**
- Rule IDs: `100280`
- Groups: `vpn_anomaly`, `vpn_login_anomaly`
- MITRE ATT&CK: `T1078` Valid Accounts (Initial Access)
- Recommended (EN): Validate the login with the user, revoke unexpected sessions and review MFA activity.
- Khuyến nghị (VI): Xác minh lần đăng nhập với người dùng, thu hồi phiên bất thường và rà soát hoạt động MFA.

## Device telemetry silent (`device-silent`)

Detects a known device that has stopped sending telemetry for the configured interval.

- Default severity: **high**
- Rule IDs: `SYSTEM_DEVICE_SILENT`
- Groups: `device_silent`, `telemetry_health`
- MITRE ATT&CK: `T1489` Service Stop (Impact)
- Recommended (EN): Verify device reachability and the log pipeline, then inspect the device for outage or tampering.
- Khuyến nghị (VI): Kiểm tra khả năng kết nối và luồng thu thập log, sau đó xác minh thiết bị có sự cố hoặc bị can thiệp.
