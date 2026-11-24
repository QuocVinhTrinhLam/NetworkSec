# Independent NetworkSec backend acceptance audit

Audit date 2026-11-24 (Asia/Saigon). The baseline is commit `94ec35deb5b2ccdf4f4743ebcccc893e6801cd23` on `main` plus the existing working-tree implementation. The earlier reports supplied the 15 criteria. Source inspection and this run's checks supplied the acceptance evidence. [Acceptance matrix](backend-acceptance-matrix.md)

## Verdicts

Of the 15 acceptance requirements, 10 are COMPLETE, four are PARTIAL and one is BLOCKED. The correlation requirement includes missing telemetry-dependent behaviors.

| Scope | Verdict | Basis |
|---|---|---|
| Backend code readiness | **PARTIAL** | Core storage, API, browser regression and the scoped lab workflows pass. Cross-source identity, audit ownership, some ingestion failure modes and telemetry-dependent rules remain open. |
| Frontend integration readiness | **PARTIAL** | OpenAPI 3.1 covers 42 operations on 35 paths. The isolated API contract and existing Edge browser workflows pass. The separate dashboard and its deployed origin were unavailable. |
| Ubuntu deployment readiness | **BLOCKED** | Template configuration passes. Runtime Compose and approved VM validation require an available Docker engine and the actual VM. |
| Live GNS3 demonstration readiness | **BLOCKED** | The checked-in topology lists one RouterOS CHR, while a dual-router live demonstration requires two confirmed reporters and their configured adjacency. The actual project and its collector path were unavailable. |
| Graduation project demonstration readiness | **PARTIAL** | A fixture-backed demonstration of the API, correlation lifecycle, reports and dashboards has repeatable software evidence. Full live acceptance requires the Ubuntu, frontend and GNS3 gates. |

## Changes verified

| ID | Severity | Confirmed behavior and remediation |
|---|---|---|
| AUD-01 | HIGH | Legacy operational cookie sessions survived server-side logout and credential changes because validity depended on signed identity alone. Operational cookies now carry a separate revocable database session with an eight-hour server-side lifetime. Bearer tokens retain their configured lifetime. Both cookie logout routes use the corresponding server store and CSRF. Existing operational cookies require fresh login. [Sessions](../app/web/accounts.py) · [Role and cookie tests](../tests/integration/test_backend_operations.py) |
| AUD-02 | HIGH | Incident projection and catalog/observation writes committed independently. The processor now projects built-in alert or OSPF state and indexes the event within one PostgreSQL transaction. A failure injected after catalog insertion rolled the alert and catalog transaction back. Retry and exact replay converged on one member. Applied migration SQL and checksums were preserved. [Catalog transaction](../app/storage/backend.py#L166) · [PostgreSQL regression](../tests/integration/test_backend_operations.py) |
| AUD-03 | HIGH | A correlated event outside Loki's ordering window could remain at the checkpoint and stop later records. New processing verifies Loki acceptance before updating the correlation journal, records acceptance durably for restart, and dead-letters the explicit permanent ordering rejection with its immutable spool coordinates. A retry after downstream failure skips a confirmed write. Tests cover the matched event, PostgreSQL failure, restart and subsequent progress. [Worker](../app/processor/worker.py) · [Checkpoint state](../app/processor/state.py#L160) · [Processor regressions](../tests/test_processor.py) |
| AUD-04 | MEDIUM | The legacy event list disclosed raw text to cookie-authenticated administrators. The shared list now returns a stable ID with a restricted raw field. Admin event detail uses explicit opt-in and recognizable-credential masking. The OSPF tests compare IDs across Loki pagination, catalog/detail and incident evidence. [API list](../app/web/api.py) · [OWASP review](backend-security-findings.md) |
| AUD-05 | MEDIUM | Alert pagination, some SQL-bound fields and extreme ranges could reach downstream storage with invalid values. The reviewed versioned routes now return 422 for these cases. Dashboard device exports honor the same `enabled` filter as the paginated device report. [API contract](api-contract.md) · [Transport tests](../tests/test_storage_api.py) |
| AUD-06 | MEDIUM | The export route's response schema omitted its JSON variants, CSV and attachment headers. The generated schema describes both representations, domain errors and validation issue variants. A test checks snapshot equality with live route declarations and exercises each protected operation without auth. [OpenAPI](openapi.json) · [Contract test](../tests/test_backend_contract.py) |

## Remaining source and operational gaps

| ID | Severity | Status | Evidence and consequence |
|---|---|---|---|
| AUD-07 | HIGH | PARTIAL | Normalized identity hashes schema, vendor, parser, reported device name, original timestamp and raw message. It excludes collector source. Two sources emitting identical normalized identity inputs collapse to one catalog row, with the first attribution retained. Built-in interface aggregation also groups by reported name/interface. Preserve the 1.0/1.1 ID contract and existing history in this patch. Confirm distinct lab reporter names. A source-aware identity change needs a versioned migration and replay plan. [ID derivation](../app/schemas/event.py#L196) · [Interface rule](../config/correlation_rules.yaml) |
| AUD-08 | HIGH | BLOCKED | The committed GNS3 project contains eight nodes, seven links and one named RouterOS CHR. Both `config/topology.yaml` and `ospf.links` contain empty inventories. Validate the operator's actual project, the separate management path, and both reporter IDs before a dual-RouterOS demo. [Checked-in topology](../gns3/topology/Network-Security-Monitoring-Lab.gns3) · [Lab procedure](ubuntu-deployment-checklist.md) |
| AUD-09 | HIGH | PARTIAL | Loki and the PostgreSQL writes cannot share a transaction. A crash between the Loki acknowledgement and the local receipt can repeat a physical Loki push. A pending PostgreSQL write can leave an event temporarily visible in the legacy Loki list before it reaches the catalog. API queries and catalog/incident membership deduplicate stable IDs. Existing events before the catalog rollout remain outside those KPIs, and Loki eviction can leave a catalog record with an unavailable payload. Manual spool rotation, raw retention and disaster recovery were outside runtime verification. [Storage and replay](../app/processor/worker.py) · [KPI coverage](kpi-contract.md) |
| AUD-10 | HIGH | PARTIAL | Audit records are transaction-coupled, with no API path to remove them. The deployed DB initialization identity can alter them. Loki/Grafana access has separate authority and can bypass the API's payload boundary. Both issues gate broader access. [Security findings](backend-security-findings.md) |
| AUD-11 | MEDIUM | PARTIAL | Managed rules use verified inputs and fixed event-time windows. There is no verified end-to-end inactivity, restart or generic network-error rule, and port flap stays disabled until a verified source exists. Alert availability percentages require a covered health interval and remain null. [Rule constraints](../app/services/managed_rules.py) · [KPI semantics](kpi-contract.md) |
| AUD-12 | MEDIUM | PARTIAL | The operational API still initializes the legacy SQLite database and mounts Jinja routes in the same process. The API data paths use PostgreSQL/Loki and their own role policies, but the shared startup and legacy UI need the `monitor-data` volume. API CPU, audit and event/incident growth, unbounded retention, and live query cost were not load-tested on Ubuntu. [Startup](../app/main.py) · [Compose services](../compose.yaml) |
| AUD-13 | MEDIUM | BLOCKED | Docker's Windows Linux engine named pipe was absent. Loki/rsyslog image health checks validate configuration, and dashboard health reports process mode. These do not establish actual collection/readiness. Three explicit checks are necessary on Ubuntu: authenticated storage readiness, live processor heartbeat, and a RouterOS event through collector to API. [Ubuntu checklist](ubuntu-deployment-checklist.md) |

## Reproducible evidence and test accounting

- **335 distinct passing Pytest IDs.** The broad run selected all 337 cases and finished with 334 passed and three skipped. The separately enabled Phase 5 storage test passed, leaving two Compose-dependent cases skipped. The original collection had 333 IDs. The 331 original runnable cases pass on the audited tree, together with four new regression cases. The fast baseline, the final 328-pass fast check and targeted reruns are excluded from the total.
- **Native storage.** PostgreSQL 16.16 and Loki 3.7.0 ran on disposable loopback state. The available PostgreSQL 17.7 Windows bundle lacked working UTC timezone data, so the integration suite used 16.16. Compose pins PostgreSQL 17.12. Fresh/idempotent migration tests and upgrade tests preserve incident and notification state. Both native OSPF variants run parser, processor, store, API and a recording Telegram gateway. No Telegram messages were sent.
- **Browser.** Six Microsoft Edge automation cases passed against the server-rendered dashboard. Screenshots and test databases were written to a temporary audit directory. This verifies the existing UI and staged workflow in an isolated environment.
- **Grafana.** Disposable Grafana 13.3.0 provisioned all three dashboards. Both datasource health checks passed and all nine KPI panel queries ran through the Grafana query API. A filtered fixture produced one event in the total panel. The dedicated PostgreSQL login queried four KPI views and had no SELECT/INSERT/UPDATE/DELETE access to account, event catalog or audit tables. The PostgreSQL regression compared all nine shipped SQL queries to the API under matching seeded filters.
- **Static checks.** Ruff lint and format, mypy, Git diff whitespace check, and `docker compose --env-file .env.example config --quiet` passed. Both Python requirements lists returned no known vulnerabilities from `pip-audit`. Starlette emitted one existing TestClient transport deprecation warning.
- **Blocked integrations.** `test_rsyslog_collects_tcp_and_udp_without_changing_raw_messages` and `test_live_pipeline_restart_replay_and_notification_deduplication` require a running Compose test environment. Live Ubuntu, GNS3 and the separate frontend were not exercised.

```powershell
python -m pytest -o addopts='' -ra --tb=short
python -m pytest tests/integration/test_phase5_storage.py
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m mypy app
python -m pip_audit -r requirements.txt
python -m pip_audit -r requirements-dev.txt
docker compose --env-file .env.example config --quiet
git diff --check
python -m scripts.export_openapi
```

For the first command point `NETWORKSEC_TEST_POSTGRES_DSN` and `NETWORKSEC_TEST_LOKI_URL` at disposable services and set `NETWORKSEC_QA_BROWSER_CHANNEL=msedge` with a temporary evidence directory. For Phase 5 set `RUN_STORAGE_INTEGRATION=1`, `POSTGRES_DSN` and `LOKI_URL` for disposable services. The Compose tests require their own explicit setup. [Testing guide](testing.md)

The operator actions and acceptance conditions are in the [Ubuntu and GNS3 checklist](ubuntu-deployment-checklist.md). The separate dashboard handoff is in the [frontend readiness checklist](frontend-readiness-checklist.md).
