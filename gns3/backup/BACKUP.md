# Backup record and strategy

## Verified local backup

Created: 2026-11-12 17:59:46 (Asia/Saigon, UTC+07:00)

Location (outside Git):
`D:\GNS3-Backups\Network-Security-Monitoring-Lab\20261112-175946`

The backup is a powered-off whole-GNS3-VM copy plus the Windows project and selected host
settings. It contains 18 checksummed content files totaling 6,866,569,691 bytes. Including
the manifest and sidecar, the directory is 6,866,577,249 bytes (approximately 6.39 GiB).

Contents:

- Windows topology from `D:\Network-Security-Monitoring-Lab`.
- Complete VMware VM directory from `D:\Vmware\GNS3 VM`.
- `GNS3 VM-disk1.vmdk` and `GNS3 VM-disk2.vmdk`, which preserve remote-compute projects,
  QEMU overlays, VPCS data, and appliance state.
- GNS3 controller, GUI, and server settings in a sensitive `host-settings` directory.
- `MANIFEST.json`, `MANIFEST.sha256`, `RESTORE.md`, and a sensitivity warning.

Manifest SHA-256:
`A6B5E66D4884EAB969048525CF094C757C310EB79F71564782DFBACD356F2B86`

## Validation performed

- VMware `vmrun list`: zero running VMs before the copy.
- No `vmware-vmx`, QEMU, VPCS, uBridge, or Dynamips process was active.
- No `.lck`, `.vmem`, or `.vmss` file was present.
- Source and destination file counts/sizes match for the project and VM.
- Topology, VMX, and both VMDKs match their sources by SHA-256.
- The copied topology parses as JSON with seven nodes and six links.
- Both copied VMDKs parse with `qemu-img info` as monolithic-sparse VMDKs.
- Every included content file has a size and SHA-256 in `MANIFEST.json`.

A full restore was not attempted. A native GNS3 portable export was not produced because
the node runtime data was on the powered-off VM compute and starting the VM was not
authorized. This limitation is explicit; the offline whole-VM copy is the restorable
state backup.

## Appliance inventory

| Component | Verified detail |
| --- | --- |
| GNS3 | 2.2.61 |
| VMware Workstation | 17.6.3 build 24583834 |
| MikroTik | CHR 7.24.6, `chr-7.24.6.img`, MD5 `d5f115c8801e855131b443cba9f2be41` |
| pfSense | `pfSense-Firewall-hda.qcow2`, MD5 `f692998d6a8ef3970a3aa833070b2a53`; release unknown |
| VPCS/switch | Built into the GNS3 VM/project; exact VPCS binary version not recorded |

## Ongoing strategy

1. Before major lab changes, stop every node and shut down the GNS3 VM cleanly.
2. Confirm zero running VMware VMs and no lock/suspend files.
3. Prefer a GNS3 portable export while the compute is available, then close the project.
4. Create a new timestamped offline whole-VM/project backup; never overwrite an older one.
5. Generate a per-file SHA-256 manifest and validate topology/VMDK readability.
6. Keep complete pfSense XML and sensitive RouterOS exports only in protected offline
   storage. Commit only reviewed, sanitized material.
7. Periodically restore to alternate paths and verify node boot/configuration.
