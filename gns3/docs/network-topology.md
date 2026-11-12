# Network topology

## Verified physical/logical links

```text
GNS3 NAT1 nat0
      |
      | pfSense adapter 0
pfSense-Firewall-1
      | pfSense adapter 1
      | MikroTik adapter 0
MikroTikCHR7.24.6-1
      | MikroTik adapter 1
      | Switch1 Ethernet0 (dot1q, persisted VLAN 1)
Switch1
      |-- Ethernet1 (access VLAN 10) -- PC1 adapter 0
      |-- Ethernet2 (access VLAN 20) -- PC2 adapter 0
      `-- Ethernet3 (access VLAN 30) -- PC3 adapter 0
```

These links and switch modes are actual values parsed from revision 9 of the GNS3 2.2.61
project. Guest interface assignments, IP addresses, routes, firewall policies, and syslog
destinations were not observable while the VM compute was powered off.

## Interface mapping

| Node | GNS3 adapter | Connected to | Interpretation |
| --- | --- | --- | --- |
| pfSense | adapter 0 | NAT1 nat0 | Intended WAN; guest assignment not verified |
| pfSense | adapter 1 | MikroTik adapter 0 | Intended LAN; guest assignment not verified |
| MikroTik | adapter 0 | pfSense adapter 1 | Intended `ether1`; RouterOS name not live-verified |
| MikroTik | adapter 1 | Switch1 Ethernet0 | Intended VLAN trunk; RouterOS config unavailable |
| PC1 | adapter 0 | Switch1 Ethernet1 | VLAN 10 access link verified in switch metadata |
| PC2 | adapter 0 | Switch1 Ethernet2 | VLAN 20 access link verified in switch metadata |
| PC3 | adapter 0 | Switch1 Ethernet3 | VLAN 30 access link verified in switch metadata |

## Monitoring path

The intended project architecture sends router/firewall security telemetry toward the
repository's monitoring stack. No syslog target was verified in pfSense or RouterOS, so
the repository must not be treated as evidence that forwarding is enabled.
