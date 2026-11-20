# pfSense Phase 7 remote Syslog — review only

Không thay `config.xml` hoặc GUI khi chưa được approval. Trước tiên xác minh LAN transit
là `10.10.0.1/30` và tạo static routes tới `10.10.10.0/24`, `10.10.20.0/24` và
`10.10.99.0/24` qua MikroTik `10.10.0.2` nếu các route chưa tồn tại.

Trong **Status > System Logs > Settings**:

1. Bật **Send log messages to remote syslog server**.
2. Chọn Source Address là LAN transit đã xác minh và IP Protocol IPv4.
3. Đặt remote server `10.10.99.10:5514`.
4. Ban đầu chỉ chọn **System Events** và **Firewall Events** để giới hạn volume.
5. Save, sau đó kiểm tra packet/line delta theo runbook Phase 7.

pfSense built-in remote Syslog chỉ dùng UDP. Dữ liệu không mã hóa; chỉ gửi qua management
lab biệt lập. Nếu cần đi qua mạng không tin cậy, dừng và thiết kế VPN/TLS thay vì mở UDP
Syslog ra WAN.

Nguồn chính thức:
[Netgate Remote Logging with Syslog](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html).
