# Restore the GNS3 lab

Use the separately stored timestamped backup referenced in `BACKUP.md`. Do not restore
from this Git directory; it intentionally excludes device disks and sensitive settings.

## Verify the backup

1. Copy the backup to stable local storage.
2. Hash `MANIFEST.json` and compare it with `MANIFEST.sha256` and the value in
   `BACKUP.md`.
3. Parse the manifest and recompute every listed file's SHA-256.
4. Run `qemu-img info` against both backed-up VMDKs.
5. Stop if any size/hash differs.

## Restore without overwriting the source

1. Confirm VMware reports zero running VMs.
2. Copy `project\Network-Security-Monitoring-Lab` to a new project path.
3. Copy `gns3-vm\GNS3 VM` to a new VMware path.
4. Register the copied VMX in VMware Workstation and choose **I copied it** if prompted.
5. Configure GNS3 2.2.61 to use the restored VMware GNS3 VM.
6. Open the restored `.gns3` file and verify seven nodes, six links, and switch ports
   before starting nodes.
7. Start only the restored lab. Verify pfSense, MikroTik, and VPCS state through their
   supported consoles/export mechanisms.
8. Compare guest configuration with the intended IP/VLAN documents before making changes.

Never run the original and restored GNS3 VMs simultaneously on the same VMware networks.
Treat `host-settings` as sensitive and merge settings selectively rather than overwriting
another workstation's configuration.

## Portable topology-only import

The committed `.gns3` file can recreate the graph after the matching appliances are
installed, but it cannot recreate configured guest state. For full recovery, the offline
VM disks are required. The first successful maintenance window should also produce and
validate a native GNS3 portable export.
