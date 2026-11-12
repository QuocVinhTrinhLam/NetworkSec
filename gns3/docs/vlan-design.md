# VLAN design

## Verified layer-2 state

| VLAN | Access port | Endpoint | Metadata status |
| ---: | --- | --- | --- |
| 10 | Switch1 Ethernet1 | PC1 | Verified |
| 20 | Switch1 Ethernet2 | PC2 | Verified |
| 30 | Switch1 Ethernet3 | PC3 | Verified |

Switch1 Ethernet0 is persisted as a GNS3 `dot1q` port with VLAN value 1 and connects to
MikroTik adapter 1. Ethernet4 through Ethernet7 are unused access ports in VLAN 1.

## Intended layer-3 design

MikroTik is intended to terminate VLANs 10, 20, and 30 and route toward pfSense over
`10.10.0.0/30`. The topology does not prove that RouterOS VLAN interfaces, IP addresses,
routes, firewall rules, NAT, or DHCP configuration exist. pfSense policy and static-route
state are likewise unverified.

## Security considerations

- Keep inter-VLAN policy deny-by-default unless the monitoring use case requires access.
- Restrict administrative services to a dedicated management path.
- Send pfSense and RouterOS logs to an authenticated, time-synchronized collector.
- Do not infer that a GNS3 `dot1q` port alone provides native-VLAN or VLAN-hopping defense;
  verify both switch metadata and RouterOS bridge/VLAN configuration.
