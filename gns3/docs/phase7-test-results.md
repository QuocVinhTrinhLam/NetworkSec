# Phase 7 test results

Ngày audit: 2026-11-19. Kết quả không trộn ba loại nguồn.

## Live device results

| Test | Status | Evidence |
|---|---|---|
| GNS3 process/API read-only check | NOT RUNNING | Không có process `gns3*`; TCP 3080 không reachable |
| CHR -> Ubuntu UDP 5514 | NOT RUN | Chưa có topology/device approval và Ubuntu access |
| IOSvL2 -> Ubuntu UDP 5514 | NOT RUN | Managed switch chưa được thêm; không có licensed image trong repo |
| Link down/up event | NOT RUN | Không thay trạng thái cổng khi chưa được approval |
| Configuration-change event | NOT RUN | Không sửa running-config khi chưa được approval |
| pfSense firewall event | NOT RUN | Nguồn tùy chọn; chưa được bật/cấu hình |

`NOT RUN` không được tính là pass/fail. Sau approval, điền UTC, source IP, packet delta,
raw-line delta và event classification; không paste raw payload hoặc credential.

## Replayed results

| Test | Status | Evidence |
|---|---|---|
| Fixture replay behavior | PASS | Loghub bytes được giữ nguyên trong unit test |
| Docker rsyslog replay | NOT RUN | Máy audit không có Docker CLI |

## Synthetic results

| Test | Status | Evidence |
|---|---|---|
| TCP/UDP generator unit behavior | PASS | Sequence, framing và datagram unit tests đạt |
| Generator -> live Ubuntu listener | NOT RUN | Cần Docker/Ubuntu collector được phê duyệt |

## Static audit results

| Check | Status | Evidence |
|---|---|---|
| Topology metadata parses | PASS | `tests/test_gns3_phase7.py` |
| Eight nodes/seven links documented | PASS | Static topology test |
| Built-in Switch1 limitation recorded | PASS | Không có managed OS/Syslog plane |
| Image/firmware added to Git | PASS | Không thêm image, firmware hoặc appliance |

Targeted command: `python -m pytest tests/test_gns3_phase7.py tests/test_syslog_generator.py -q`.
Kết quả: `10 passed` (3 static Phase 7, 7 replay/synthetic generator).
