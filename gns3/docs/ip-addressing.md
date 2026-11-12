# IP addressing plan

All values in this document are **intended**, supplied by the project owner. None was
verified against guest configuration because the GNS3 VM and nodes remained powered off.

| Segment/interface | Intended address or prefix | Status |
| --- | --- | --- |
| pfSense WAN | DHCP from GNS3 NAT | Planned; not verified |
| pfSense LAN | `10.10.0.1/30` | Planned; not verified |
| MikroTik uplink (`ether1` intended) | `10.10.0.2/30` | Planned; not verified |
| VLAN 10 | `10.10.10.0/24` | Planned; switch VLAN ID verified, L3 gateway not verified |
| VLAN 20 | `10.10.20.0/24` | Planned; switch VLAN ID verified, L3 gateway not verified |
| VLAN 30 | `10.10.30.0/24` | Planned; switch VLAN ID verified, L3 gateway not verified |
| PC1 | `10.10.10.10/24` | Planned; VPCS startup unavailable |
| PC2 | `10.10.20.10/24` | Planned; VPCS startup unavailable |
| PC3 | `10.10.30.10/24` | Planned; VPCS startup unavailable |

The `/30` transit has usable addresses `10.10.0.1` and `10.10.0.2`. Default gateways for
the three client VLANs were not supplied or verified and are deliberately not invented.

Before deployment, collect `config.xml`, a RouterOS `/export show-sensitive=no`, and each
VPCS `startup.vpc`; compare them with this plan and record any differences.
