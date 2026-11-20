# Phase 7 — GNS3 Network Log Integration

## Trạng thái và phạm vi an toàn

Tài liệu này là runbook **review-first**. Không lệnh cấu hình thiết bị nào đã được áp
dụng. Không project/node GNS3 nào được start, stop, nối lại cáp hoặc sửa cấu hình trong
Phase 7 này. Kiểm tra read-only ngày 2026-11-19 không thấy GNS3 process hoặc API local
`127.0.0.1:3080`, vì vậy kết quả live vẫn là `NOT RUN`.

Không đưa image IOSvL2/CHR/pfSense, firmware, export chứa credential, packet capture hoặc
raw log live vào Git. Chỉ sử dụng image Cisco có quyền sử dụng hợp lệ.

## Audit topology hiện tại

Snapshot `Network-Security-Monitoring-Lab.gns3` là GNS3 2.2.61, revision 9, hiện có tám
node và bảy link:

```text
NAT1 -- pfSense-Firewall-1 -- MikroTikCHR7.24.6-1 -- Switch1
                                                        |-- PC1       VLAN 10
                                                        |-- PC2       VLAN 20
                                                        |-- PC3       VLAN 30
                                                        `-- webterm-1 VLAN 10
```

`Switch1` là built-in Ethernet Switch, không có management plane hoặc Syslog. Vì thế nó
không thỏa target “managed switch with real Syslog capability”. Guest IP, RouterOS VLAN,
route, pfSense route và Syslog target chưa thể xác minh từ metadata.

## Topology đề xuất nhẹ

```text
                    optional, chỉ bật khi test firewall
GNS3 NAT ---- pfSense ---- MikroTik CHR R1
                              | ether2: trunk 10,20,99
                              |
                         Cisco IOSvL2 SW1
                         | Gi0/1  VLAN 10 -- PC1 Test Host
                         | Gi0/2  VLAN 20 -- webterm-1 Admin Host
                         | Gi0/3  VLAN 99 -- Cloud-MGMT -- Ubuntu collector NIC
                         ` Gi0/4  VLAN 10 -- port test dự phòng
```

- Giữ CHR hiện hữu; không tạo router thứ hai.
- Dùng PC1 làm Test Host và `webterm-1` làm Admin Host. PC2/PC3 giữ nguyên nhưng power
  off; không xóa để tránh thay đổi phá hủy.
- Thay built-in Switch1 bằng IOSvL2 chỉ sau khi snapshot/approval. IOSvL2 được GNS3 hỗ
  trợ như managed multilayer switch; GNS3 không phân phối Cisco image.
- pfSense là nguồn tùy chọn. Để tiết kiệm RAM, chỉ bật nó trong bài test firewall.
- Cloud-MGMT là bridge L2, không có IP. Nó bind vào NIC management riêng của GNS3 VM,
  NIC này cùng host-only network với NIC thứ hai của Ubuntu VM. Không bind Cloud vào
  Wi-Fi/public NIC.
- Host-only VMnet phải tắt DHCP. Ubuntu giữ default route trên NIC chính; NIC Syslog chỉ
  có connected route để tránh asymmetric routing.

Các thay đổi topology trên là **đề xuất**, chưa áp dụng.

## Kế hoạch địa chỉ và routing

| Thành phần | Interface/segment | Địa chỉ đề xuất | Gateway/route |
|---|---|---|---|
| pfSense | LAN transit | `10.10.0.1/30` | static routes qua `10.10.0.2` |
| MikroTik R1 | `ether1` transit | `10.10.0.2/30` | default `10.10.0.1` nếu cần Internet |
| MikroTik R1 | VLAN 10 | `10.10.10.1/24` | gateway Test |
| MikroTik R1 | VLAN 20 | `10.10.20.1/24` | gateway Admin |
| MikroTik R1 | VLAN 99 | `10.10.99.1/24` | gateway management |
| IOSvL2 SW1 | SVI VLAN 99 | `10.10.99.2/24` | `10.10.99.1` |
| PC1 | VLAN 10 | `10.10.10.10/24` | `10.10.10.1` |
| webterm-1 | VLAN 20 | `10.10.20.10/24` | `10.10.20.1` |
| Ubuntu collector | Syslog NIC | `10.10.99.10/24` | không đặt default gateway |

pfSense chỉ cần route `10.10.10.0/24`, `10.10.20.0/24` và `10.10.99.0/24` qua
`10.10.0.2` khi nó tham gia lab. Syslog từ R1/SW1 tới collector nằm trong hoặc route tới
VLAN 99; Syslog từ pfSense đi qua transit rồi R1 tới VLAN 99.

## Ubuntu collector

Trong `.env` cục bộ, đặt listener vào đúng NIC lab:

```dotenv
SYSLOG_BIND_HOST=10.10.99.10
SYSLOG_TCP_PORT=5514
SYSLOG_UDP_PORT=5514
```

Sau khi đã phê duyệt triển khai Ubuntu:

```bash
docker compose config --quiet
docker compose up -d --wait rsyslog
docker compose ps rsyslog
ss -ltn 'sport = :5514'
ss -lun 'sport = :5514'
```

Firewall chỉ allow subnet quản trị trên đúng interface, thay `<mgmt-if>` bằng tên đã xác
minh bằng `ip -br address`:

```bash
sudo ufw allow in on <mgmt-if> from 10.10.99.0/24 to 10.10.99.10 port 5514 proto udp
sudo ufw allow in on <mgmt-if> from 10.10.99.0/24 to 10.10.99.10 port 5514 proto tcp
```

MikroTik Syslog format chỉ dùng UDP theo tài liệu RouterOS; TCP vẫn được giữ cho Cisco
hoặc synthetic test. Không bind `0.0.0.0` và không forward port 5514 ra Internet.

## Cấu hình thiết bị — chỉ áp dụng sau approval

- MikroTik CHR: review
  [`R1-phase7-syslog.rsc.example`](../configs/mikrotik/R1-phase7-syslog.rsc.example),
  so sánh với `/export show-sensitive=no`, rồi chỉ áp dụng phần còn thiếu.
- Cisco IOSvL2: review
  [`SW1-iosvl2-phase7.cfg.example`](../configs/switch/SW1-iosvl2-phase7.cfg.example).
  Dùng `show interfaces status`, `show vlan brief` và `show logging` để xác minh tên cổng
  và feature support trước khi lưu.
- pfSense tùy chọn: làm theo
  [`PFSENSE-phase7-remote-syslog.md`](../configs/pfsense/PFSENSE-phase7-remote-syslog.md).

Không paste toàn bộ fragment vào thiết bị đã có cấu hình. Không ghi credential hoặc
community string vào Syslog/config archive. Cisco `hidekeys` phải được bật trước
`notify syslog`.

## Kiểm chứng live có kiểm soát

### 1. Baseline không in payload

```bash
docker compose exec -T rsyslog sh -c \
  'test -f /var/log/networksec/raw.log && wc -l /var/log/networksec/raw.log || echo 0'
sudo tcpdump -ni <mgmt-if> -c 20 \
  'udp port 5514 and (host 10.10.99.1 or host 10.10.99.2)'
```

Không dùng `tcpdump -A/-X` trong evidence vì payload có thể chứa username, địa chỉ hoặc
nội dung cấu hình. Ghi lại timestamp UTC, source IP, packet count và raw line count trước/
sau; không copy raw payload vào tài liệu hoặc issue công khai.

### 2. Network reachability

- R1: ping `10.10.99.10` với source `10.10.99.1`.
- SW1: ping `10.10.99.10` với source VLAN 99 nếu image hỗ trợ tùy chọn source.
- Ubuntu: kiểm tra ARP/neighbour cho `10.10.99.1` và `10.10.99.2`.
- pfSense tùy chọn: ping collector bằng Source Address LAN sau khi static route tồn tại.

### 3. Operational event

Trên cổng test không mang management/uplink, sau approval thực hiện `shutdown`, đợi ít
nhất hai giây rồi `no shutdown`. Kỳ vọng Cisco phát `%LINK-3-UPDOWN`; xác minh packet từ
`10.10.99.2` và raw line count tăng. Không flap trunk, VLAN 99 hoặc cổng collector.

### 4. Configuration event

Trên cùng cổng test, đổi một description vô hại rồi khôi phục. Với config archive đã bật,
kỳ vọng Syslog cấu hình (`%SYS-5-CONFIG_I` hoặc notification mà image thực tế phát).
Ghi format live chính xác vào fixture mới chỉ sau khi đã loại dữ liệu nhạy cảm; không sửa
parser để khớp một format suy đoán.

### 5. MikroTik và pfSense

- Sau khi action/rule được duyệt, dùng một `/log warning` có marker không nhạy cảm để
  kiểm tra đường truyền MikroTik. Đây là **live diagnostic**, không phải operational event.
- Tạo tối đa một lần đăng nhập thất bại với username lab không tồn tại nếu chính sách
  lockout cho phép; không ghi password vào command/evidence.
- Với pfSense, bật một firewall rule test có logging và tạo một packet bị deny từ Test
  Host. Không thay rule production hoặc expose dịch vụ mới.

## Parser compatibility gate

Raw delivery thành công không đồng nghĩa parsing thành công. Parser hiện chỉ chấp nhận
các format đã có fixture. Remote Syslog có thể thêm PRI/hostname hoặc timestamp khác. Mọi
format live mới trước tiên phải được lưu trong raw spool, khử dữ liệu nhạy cảm, thêm fixture
và regression test; unknown event phải tiếp tục an toàn thay vì được “đoán” theo vendor.

## Phân loại kết quả

| Loại | Nguồn | Bằng chứng bắt buộc |
|---|---|---|
| Live | CHR/IOSvL2/pfSense đang chạy | source IP, UTC, packet/line delta, event type |
| Replayed | fixture/Loghub qua generator | fixture path, count, protocol, test result |
| Synthetic | Python generator sequence ID | sequence range, rate, transport, gap/duplicate |

Không cộng replay/synthetic vào số liệu “thiết bị live”. Kết quả thực tế của lần triển khai
này nằm tại [phase7-test-results.md](phase7-test-results.md).

## Rollback

Nếu live test thất bại, dừng test event trước; không xóa volume. Gỡ riêng logging rule/action
đã thêm hoặc restore snapshot/config export đã được phê duyệt. Dừng collector bằng
`docker compose stop rsyslog`; không dùng `down -v`. Revert cáp/IP chỉ theo sơ đồ trước
thay đổi đã ghi lại, không reset toàn project.

## Tài liệu chính thức

- [GNS3 Cloud/NAT connectivity](https://docs.gns3.com/docs/using-gns3/advanced/connect-gns3-internet)
- [GNS3 VMware host-only networks](https://docs.gns3.com/docs/emulators/adding-vmware-vms-to-gns3-topologies)
- [GNS3 IOSvL2 appliance and licensing note](https://docs.gns3.com/docs/using-gns3/beginners/install-from-marketplace)
- [MikroTik RouterOS logging](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log)
- [Cisco configuration change logging](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-logger-0.html)
- [pfSense remote Syslog](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html)
- [rsyslog UDP input](https://docs.rsyslog.com/doc/configuration/modules/imudp.html)
- [rsyslog TCP input](https://docs.rsyslog.com/doc/configuration/modules/imtcp.html)
