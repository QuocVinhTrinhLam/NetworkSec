# GNS3 network lab

This directory contains the version-controlled, non-sensitive representation of the
`Network-Security-Monitoring-Lab` project. It complements the Network Event Management application in
the repository; it does not contain virtual disks or a complete device-state backup.

## Verified snapshot

The snapshot was inspected on 2026-11-12 with GNS3 2.2.61. The source project is
`D:\Network-Security-Monitoring-Lab\Network-Security-Monitoring-Lab.gns3` and uses the
VMware compute named `GNS3 VM`. The current topology JSON contains eight nodes and seven
links after `webterm-1` was connected to Switch1 Ethernet4 on VLAN 10.

Verified from the project metadata:

- NAT1 connects to pfSense adapter 0.
- pfSense adapter 1 connects to MikroTik adapter 0.
- MikroTik adapter 1 connects to Switch1 Ethernet0.
- Switch1 Ethernet1, Ethernet2, and Ethernet3 connect to PC1, PC2, and PC3.
- Switch1 Ethernet4 connects to `webterm-1` as an access port in VLAN 10.
- Ethernet0 is a `dot1q` port; Ethernet1/2/3 are access ports in VLAN 10/20/30.
- MikroTik uses the `chr-7.24.6.img` appliance image.
- pfSense uses `pfSense-Firewall-hda.qcow2`; the pfSense release is not present in the
  topology metadata.

The IP plan in `docs/ip-addressing.md` is the intended design supplied for the project.
It was not verified against the powered-off guests.

## Contents

- `topology/`: sanitized copy of the GNS3 topology metadata.
- `configs/`: verified switch metadata and explicit export-availability records.
- `docs/`: topology, IP plan, VLAN design, and interface mapping.
- `backup/`: backup and restore procedures; no backup payloads.

## Reproduce the lab

1. Install GNS3 2.2.61 and a compatible VMware Workstation/GNS3 VM.
2. Install legally obtained pfSense and MikroTik CHR images matching the filenames and
   checksums documented in `backup/BACKUP.md`.
3. Open `topology/Network-Security-Monitoring-Lab.gns3` in GNS3.
4. Resolve the VM compute and appliance-image prompts without changing node IDs.
5. Confirm the eight-node/seven-link topology and switch VLANs before starting devices.
6. Restore device configurations only from trusted exports. The repository does not
   contain an actual pfSense XML, RouterOS export, or VPCS startup export.
7. Apply the intended IP plan only after comparing it with the restored device state.

For whole-state recovery, follow `backup/RESTORE.md` and use the separately stored
offline backup. Never add that backup or its virtual disks to Git.

## Known limitations

- No guest was started or modified during collection.
- Supported live exports require the VM compute and guest nodes to be running; they were
  intentionally left powered off.
- A complete restore rehearsal was not performed.
- Switch1 is the unmanaged GNS3 built-in switch and cannot originate Syslog. See the
  [Phase 7 review-only integration runbook](docs/phase7-syslog-integration.md).
- The committed topology omits the MikroTik appliance help text because it mentioned
  factory-default credentials; this does not change node or link behavior.
