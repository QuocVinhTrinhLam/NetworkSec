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
| Proposed management VLAN 99 | `10.10.99.0/24` | Phase 7 plan; not applied |
| Proposed MikroTik VLAN 99 gateway | `10.10.99.1/24` | Phase 7 plan; not applied |
| Proposed managed-switch SVI | `10.10.99.2/24` | Phase 7 plan; not applied |
| Proposed Ubuntu Syslog NIC | `10.10.99.10/24` | Phase 7 plan; not applied |

The `/30` transit has usable addresses `10.10.0.1` and `10.10.0.2`. Phase 7 proposes
`.1` gateways on VLAN 10, 20 and 99, but none has been verified or applied. VLAN 30 keeps
its earlier unverified status and is outside the lightweight Phase 7 topology.

Before deployment, compare a RouterOS `/export show-sensitive=no` and each available VPCS
`startup.vpc` with this plan. Validate pfSense addressing/routes in its GUI without copying
`config.xml` into the repository because that file may contain sensitive material.
