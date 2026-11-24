# GNS3 live validation

**Live status: BLOCKED.** On 2026-11-24 the local environment had no GNS3 or syslog listener on ports 3080 and 5514, and the Docker Desktop Linux engine was unavailable. The Ubuntu lab requires an operator endpoint and approved test scope.

Two fixture-backed pipeline tests passed against native disposable PostgreSQL and Loki. They exercised RouterOS and Cisco down/recovery evidence, including a dual-RouterOS case. The browser suite uses a local test application. The native Grafana check exercised datasource health and panel SQL with seeded data. These runs are software evidence. Device addresses, the management route, area, router IDs and interfaces need operator confirmation from the actual lab. See the [acceptance report](../../backend-final-report.md) for executed tests and the [Ubuntu deployment](../../deployment.md#điều-kiện-lab-và-checklist-nghiệm-thu-live) for lab context.

Configure `NETWORKSEC_TEST_POSTGRES_DSN` and `NETWORKSEC_TEST_LOKI_URL` for disposable local services before rerunning the fixture pipeline.

```sh
python -m pytest tests/integration/test_postgres_ospf_lifecycle.py -k spool_to_loki
```

## Passive checks on the Ubuntu lab

Use the operator-approved host and Compose project. Use management-network addresses recorded for that deployment.

```bash
docker compose config --quiet
docker compose ps
docker compose port --protocol udp rsyslog 5514
docker compose port --protocol tcp rsyslog 5514
docker compose exec -T processor python -m app.processor.healthcheck
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3100/ready
curl -fsS http://127.0.0.1:3000/api/health
```

Confirm the published TCP/UDP bindings match the syslog configuration on the devices. Use the known management route so collector connectivity persists during a transit-link failure. Inspect both routers with these RouterOS read-only commands and record only the required, non-sensitive fields.

```text
/routing/ospf/instance/print detail
/routing/ospf/neighbor/print detail
/routing/ospf/interface/print detail
/system/logging/action/print detail where target=remote
```

RouterOS v7 documents the OSPF interface and neighbor menus for monitoring. [MikroTik RouterOS v7 manual](https://manual.mikrotik.com/docs/getting-started/upgrading-to-v7).

From an authenticated Dashboard session, inspect `GET /api/v1/storage/health` and the current `/api/v1/topology`. Compare the observed collector addresses to the approved registry and configured `ospf.links`. Record counts and timestamps from existing logs first.

## Acceptance scenarios

| Scenario | Steps and expected evidence | Live result |
|---|---|---|
| Normal logging | Observe a known event from each router. Compare collector spool size/count deltas, API event detail vendor/collector IP, registry attribution, and Grafana activity. | Pending |
| Dual-router failure | Wait for a scheduled event or use an operator-approved lab action. Confirm both Down observations, one mapped adjacency ID, one affected incident and both references. | Pending |
| Recovery | Observe the end of the scheduled event. Confirm newer Full signals from every Down reporter and a recovery transition on the same incident ID. | Pending |
| Duplicate failure | Use the approved replay/fixture procedure on an isolated test collector. Reissue the same Down record and show stable distinct catalog counts and incident IDs. | Pending |
| Repeated event | Observe separate event IDs from distinct RouterOS messages in the same outage. Confirm one active OSPF incident with additional evidence. | Pending |
| Unregistered source | Use an approved temporary test source without registry attribution. Confirm a parsed collector event has a null registry ID. | Pending |
| Invalid record | On the disposable test collector, submit a fixture the parser rejects. Confirm a dead-letter increment and a subsequent valid event processed normally. | Pending |
| Restart and replay | During an approved test window, restart the processor, then collector as applicable. Confirm health, checkpoint reuse, recovery from the persisted queue, and stable incident/catalog counts. | Pending |

For ingestion checks, compare `/api/v1/events/catalog`, `/api/v1/dashboard/summary`, and the **Network Event KPIs** dashboard with identical UTC boundaries and supported filters. Compare device and transition metadata through `/api/v1/events/{event_id}`, `/api/v1/alerts/{alert_id}/evidence`, and `/api/v1/topology`.

These commands restart the processor and collector in the approved disposable environment.

```bash
docker compose restart processor
docker compose exec -T processor python -m app.processor.healthcheck
docker compose restart rsyslog
docker compose ps
```

For each executed scenario, add the UTC time range, a pseudonym for the source, test observer, distinct event and incident counts, and the resulting state or error class. Keep credentials, original packets, raw messages and device configuration in the operator's controlled evidence store. Record unsuccessful and unexecuted scenarios explicitly.
