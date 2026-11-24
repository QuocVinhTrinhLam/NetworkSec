# Ubuntu deployment and GNS3 acceptance checklist

**Verdict · BLOCKED.** Docker Compose accepted the template on the audit workstation. The Docker Linux engine and an operator-confirmed Ubuntu and GNS3 endpoint were unavailable. Native PostgreSQL, Loki and Grafana evidence has a separate runtime scope.

## Existing Ubuntu VM

- [ ] Identify the VM, repository revision, Compose project, existing volume names and maintenance window. Preserve the current project name and named volumes. Use the existing approved SSH path. Check `docker version`, `docker compose version`, `df -h`, `free -h` and `timedatectl status`.
- [ ] Check the protected runtime environment on the VM. Set mode 0600 on its environment file. Confirm a strong unique session secret, bootstrap password hash and unique PostgreSQL and Grafana credentials. The current libpq key/value template expects an interpolation-safe PostgreSQL password. Set the exact HTTPS frontend origin, trusted hosts including loopback health-check names, and the browser-facing Grafana URL. On HTTPS set `SESSION_HTTPS_ONLY=true`. Preserve loopback host bind defaults and use the approved tunnel or reverse proxy. [Existing deployment configuration](deployment.md)
- [ ] Confirm the collector binds only to the approved lab NIC and its firewall allows UDP/TCP 5514 only from lab sources. Keep PostgreSQL, Loki, Grafana and the dashboard on their approved bindings. Review the Grafana audience and PostgreSQL runtime-role limitations before granting general access. [Security findings](backend-security-findings.md)
- [ ] Confirm the prior revision and take a protected backup of PostgreSQL, Loki, Grafana, `monitor-data`, and the collector spool/queue and processor-state volumes. Coordinate a consistent storage snapshot with the operator. Preserve authorization metadata on backup files. A PostgreSQL schema rollback requires rehearsal with a restore copy because the migration runner verifies checksums and applies forward changes.

Run the database backup and archive validation from the approved Compose project working directory. Set `NETWORKSEC_BACKUP_DIR` to the operator-controlled backup directory first.

```bash
umask 077
backup="$NETWORKSEC_BACKUP_DIR/networksec-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T postgres sh -c 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$backup"
test -s "$backup"
docker compose exec -T postgres pg_restore --list < "$backup" > /dev/null
```

- [ ] In the approved window, validate the real Compose environment and start the reviewed revision. The default command excludes the optional Telegram, mock and syslog-generator profiles. Investigate any failed dependency or restart before proceeding.

```bash
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 180
docker compose ps --all
docker compose port --protocol udp rsyslog 5514
docker compose port --protocol tcp rsyslog 5514
docker compose exec -T processor python -m app.processor.healthcheck
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3100/ready
curl -fsS http://127.0.0.1:3000/api/health
docker compose exec -T postgres sh -c 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT version, applied_at FROM schema_migrations ORDER BY version"'
```

The URLs above use the default published ports. Adjust them to match the confirmed Compose port mapping. The API `/health` is a process check. The Loki and rsyslog container health checks validate configuration. Require the explicit Loki readiness check, the processor heartbeat and an authenticated `GET /api/v1/storage/health` with both dependencies `ready`. Confirm migration versions 001–010 appear once. [Compose CLI](https://docs.docker.com/reference/cli/docker/compose/up/)

- [ ] Configure the PostgreSQL datasource with only the documented view grants and verify both Grafana datasource health checks. Test the non-admin API role and incident deep link separately. Keep Grafana's Loki queries within the authorized operator audience. [Grafana provisioning](grafana-integration.md)
- [ ] Capture restart counts, resource use, syslog spool/queue growth, processor health and the UTC acceptance window. Confirm disk retention and backup/restore for the raw spool, processor checkpoints, database and Loki. If any critical check fails, preserve that evidence and use the rehearsed rollback on the same volumes or the operator-controlled restore copy.

## Read-only GNS3 and RouterOS checks

Use the operator-approved existing GNS3 project and consoles. For a v2 controller on an approved local endpoint, set `GNS3_URL` and the confirmed `GNS3_PROJECT_ID`. On other versions use the GUI's node and link inspector. If authentication is required, use the operator's existing authenticated client or protected curl configuration. Record only the node names, status, UUID aliases, and selected link endpoint adapter/port names.

```bash
curl -fsS "$GNS3_URL/v2/version"
curl -fsS "$GNS3_URL/v2/projects" | jq '.[] | {name, project_id, status}'
curl -fsS "$GNS3_URL/v2/projects/$GNS3_PROJECT_ID/nodes" |
  jq '.[] | {name, node_id, status, node_type}'
curl -fsS "$GNS3_URL/v2/projects/$GNS3_PROJECT_ID/links" |
  jq '.[] | {link_id, nodes: [.nodes[] | {node_id, adapter_number, port_number}]}'
```

Match the actual transit adjacency and the separate management route to the Ubuntu collector. The checked-in project has one CHR. For the dual-router demonstration, require a confirmed running project with both reporters. The repository’s `10.10.99.0/24` design is an inventory reference. Confirm the actual CIDR, source IPs and VLAN/Cloud connection with the operator. [GNS3 v2 link API](https://github.com/gns3/gns3-server/blob/master/docs/api/v2/controller/link/projectsprojectidlinks.rst) · [GNS3 v2 node API](https://github.com/gns3/gns3-server/blob/master/docs/api/v2/controller/node/projectsprojectidnodes.rst)

On each RouterOS v7 console run the following read-only checks.

```text
/system/identity/print
/system/clock/print
/routing/ospf/instance/print detail
/routing/ospf/area/print detail
/routing/ospf/interface/print detail
/routing/ospf/neighbor/print detail
/system/logging/action/print detail where target=remote
/system/logging/print detail
/log/print count-only where topics~"ospf"
```

Compare the configured action, remote address/port, source address and OSPF topics with Ubuntu's existing binding and the registry. RouterOS BSD syslog uses UDP. Check the running version's field names and use the collector source observed on Ubuntu for attribution. Record matching scope, area, router IDs, reporter names and interfaces for both ends before scheduling any mapping update. [RouterOS logging](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log) · [RouterOS OSPF monitoring](https://help.mikrotik.com/docs/spaces/ROS/pages/331612216/routing+ospf)

Record collector file sizes and processor health before and after an existing or scheduled benign log event. These checks read spool metadata only.

```bash
docker compose exec -T rsyslog sh -c 'wc -c /var/log/networksec/processor.jsonl'
docker compose exec -T processor python -m app.processor.healthcheck
```

1. Sign in through the approved endpoint. Query `GET /api/v1/events/catalog?device_name=<reported-name>&vendor=mikrotik` with explicit UTC `start` and `end`. Check each expected reporter appears with the correct collector source and registry UUID. Open one event by ID and verify it has `payload_status=available`.
2. Observe a scheduled OSPF outage and recovery in the approved lab window. Compare `/api/v1/topology`, `/api/v1/alerts`, and `/api/v1/alerts/{alert_id}/evidence`. Acceptance requires a single incident for the mapped adjacency, two distinct reporters, no premature recovery and newer Full observations from each failed reporter. The incident ID remains stable through recovery.
3. Compare API summary and Grafana for an identical UTC window and matching supported filters. Record exact counts and the catalog coverage start. Repeat after the operator-approved restart window to confirm checkpoint recovery. Use the isolated collector for duplicate replay, invalid-record and unregistered-source tests.
4. Record timestamp, pseudonym, observed count, pass/fail or blocked reason, and evidence location for all eight scenarios. Keep original logs and captures in the protected operator store. Any topology, routing, VMware, Windows network or production database change requires explicit approval. [Scenario checklist](evidence/gns3-validation/README.md)
