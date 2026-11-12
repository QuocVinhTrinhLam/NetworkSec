# pfSense configuration export

Status: **actual `config.xml` unavailable**.

The pfSense QEMU node was powered off and its runtime filesystem resides on the GNS3 VM
compute. No guest was started and no live configuration was changed. The repository
therefore contains no fabricated interface, firewall, NAT, route, or syslog export.

The complete pfSense disk overlay is preserved indirectly inside the separately stored,
sensitive whole-GNS3-VM backup. That backup must not be committed.

At the next authorized maintenance window, use pfSense **Diagnostics > Backup & Restore**
to download a native configuration backup. Keep the complete XML offline because it can
contain password hashes, certificates, VPN secrets, SNMP communities, and other sensitive
material. If a Git-safe representation is needed, sanitize those fields and document the
redactions; `.gitignore` blocks `gns3/configs/pfsense/config.xml` by design.

The intended addressing in `../../docs/ip-addressing.md` is not proof of the guest's
current configuration.
