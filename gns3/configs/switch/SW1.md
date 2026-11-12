# Switch1 verified configuration

Source: `topology/Network-Security-Monitoring-Lab.gns3`, inspected 2026-11-12.

Switch1 is the built-in GNS3 Ethernet switch, not a managed switch OS. Its configuration
is persisted in the node's `properties.ports_mapping` array inside the `.gns3` file.

| Port | Persisted type | VLAN | Connected peer | Verification |
| --- | --- | ---: | --- | --- |
| Ethernet0 | `dot1q` | 1 | MikroTik adapter 1 | Actual metadata |
| Ethernet1 | `access` | 10 | PC1 adapter 0 | Actual metadata |
| Ethernet2 | `access` | 20 | PC2 adapter 0 | Actual metadata |
| Ethernet3 | `access` | 30 | PC3 adapter 0 | Actual metadata |
| Ethernet4 | `access` | 1 | Unconnected | Actual metadata |
| Ethernet5 | `access` | 1 | Unconnected | Actual metadata |
| Ethernet6 | `access` | 1 | Unconnected | Actual metadata |
| Ethernet7 | `access` | 1 | Unconnected | Actual metadata |

`dot1q` is the exact GNS3 port type. The VLAN value `1` is the persisted native/default
VLAN value for Ethernet0; it does not prove a RouterOS native-VLAN configuration.
