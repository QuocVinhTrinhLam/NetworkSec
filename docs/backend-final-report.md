# NetworkSec backend acceptance report

## Executive summary

The repository now serves the separate Custom Dashboard through a versioned FastAPI API with event investigation, incident-linked OSPF topology, a PostgreSQL device registry, managed rules, revocable authentication, role checks, audit records and bounded reports. The processor reuses the existing parsers, SQLite journal, Loki and PostgreSQL incident lifecycle. An event catalog makes event lookups and dashboard counts replay-safe. Grafana uses restricted PostgreSQL KPI views and retains its Loki datasource for log analysis.

The software was exercised with disposable PostgreSQL 16, Loki 3.7 and Grafana 13.3. The original GNS3 environment and Ubuntu deployment remain unverified. The inventory and OSPF configuration require confirmed lab facts before the production graph can represent R1 and R2.

## Original repository state

The audit started from `94ec35d` on `main` with existing edits in the processor, Loki storage, Compose, documentation and tests. The existing stack supplied vendor parsers, normalized event contracts 1.0 and 1.1, replay handling, Loki cursor pagination, PostgreSQL incident state, OSPF lifecycle logic, Telegram notification delivery and a legacy Jinja dashboard. The initial audit records source-level evidence for all 15 requests. The pre-change suite passed 282 tests and skipped 27 with infrastructure or browser tests excluded. [Initial audit](backend-audit.md)

## Implementation

- The event catalog persists a unique event ID, normalized metadata, collector source and receipt timing after Loki accepts the event. Event detail uses the same ID to locate the Loki payload and the PostgreSQL incident references. Raw syslog remains in the restricted collector spool.
- Device registry mutations preserve UUIDs and historical associations. Only enabled devices with a matching collector source address and compatible vendor receive new associations. Device activity reflects configured logging policy and observed data.
- Configured topology works without a running simulator. OSPF link state uses explicit scope, area and endpoint mappings, observations from each router, and existing technical recovery evidence. Unmapped observations have no target node. Links can remain unknown.
- Managed rules use bounded declarative matching, scoped grouping, thresholds, deterministic event-time windows, revisions, and in-memory or isolated simulation. Verified interface recovery retains historical evidence and respects operator resolutions. The built-in OSPF correlation policy remains configuration-owned.
- The dashboard summary and reports share event and incident definitions. PostgreSQL KPI views expose the same definitions to Grafana while excluding event messages and application security data.
- The browser frontend uses expiring opaque bearer sessions. The legacy administrator dashboard retains its CSRF-protected browser session. API roles and resource permissions apply on the backend.

## File inventory

| Area | Updated existing files | Added files |
|---|---|---|
| Runtime configuration and worker | `.env.example`, `compose.yaml`, `app/config.py`, `app/main.py`, `app/processor/__main__.py`, `app/processor/worker.py` | `config/topology.yaml` |
| API and authorization | `app/web/api.py`, `app/web/auth.py`, `app/web/routes.py` | `app/web/accounts.py`, `app/web/backend.py`, `app/web/body_limit.py`, `app/schemas/backend.py` |
| Storage and correlation | `app/storage/postgres.py`, `app/schemas/correlation.py`, `app/services/correlation.py`, `app/services/ospf_correlation.py` | `app/storage/backend.py`, `app/storage/interface_state.py`, `app/storage/managed_rules.py`, `app/services/backend.py`, `app/services/grafana.py`, `app/services/managed_rules.py`, `app/services/topology.py`, migrations 006–009 |
| Grafana | Existing dashboard and datasource provisioning reused | `infra/grafana/dashboards/network-event-kpis.json`, `infra/grafana/kpi-postgres.datasource.example.json` |
| Verification | `tests/integration/test_postgres_ospf_lifecycle.py` | `tests/integration/test_backend_operations.py`, `tests/integration/test_interface_rule_recovery.py`, `tests/test_backend_contract.py`, `tests/test_grafana_link.py` |
| Documentation | `README.md`, `docs/api.md`, `docs/architecture.md`, `docs/correlation.md`, `docs/deployment.md` | Backend audit, plan, progress and acceptance report, API and KPI contracts, frontend and Grafana guides, security review and GNS3 validation record |

## API endpoint inventory

All paths below use `/api/v1`. The API contract lists method, role, request and response schema, examples and error behavior. [API contract](api-contract.md)

| Area | Routes |
|---|---|
| Auth and users | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /users`, `POST /users`, `PATCH /users/{username}` |
| Dashboard and storage | `GET /dashboard/summary`, `GET /storage/health`, `GET /grafana/link` |
| Events | `GET /events`, `GET /events/catalog`, `GET /events/{event_id}`, `GET /events/{event_id}/related` |
| Incidents | `GET /alerts`, `GET /alerts/{alert_id}`, `GET /alerts/{alert_id}/evidence`, `POST /alerts/{alert_id}/acknowledge`, `PATCH /alerts/{alert_id}/status` |
| Topology | `GET /topology`, `GET /topology/nodes`, `GET /topology/links`, `GET /topology/nodes/{device_id}` |
| Devices | `GET /devices`, `POST /devices`, `GET /devices/{device_id}`, `PATCH /devices/{device_id}`, `DELETE /devices/{device_id}`, `GET /devices/{device_id}/events`, `GET /devices/{device_id}/incidents` |
| Rules | `GET /rules`, `POST /rules`, `GET /rules/{rule_id}`, `PATCH /rules/{rule_id}`, `DELETE /rules/{rule_id}`, `POST /rules/{rule_id}/validate`, `POST /rules/{rule_id}/test` |
| Reporting and audit | `GET /reports/summary`, `GET /reports/events`, `GET /reports/incidents`, `GET /reports/devices`, `GET /reports/export`, `GET /audit-logs` |

## PostgreSQL schema changes

| Migration | Purpose |
|---|---|
| 006 | Adds device and collector source registries, event catalog, OSPF observations, API accounts and sessions, application audit, and an incident audit trigger. |
| 007 | Adds managed rule definitions, revision-scoped windows and deduplicated membership, with defaults for verified event types. |
| 008 | Adds Grafana views for incidents, event membership and device status alongside the event facts view. |
| 009 | Adds interface lifecycle recovery evidence and projects interface activity into incident classification without dropping existing aggregate history. |

Startup applies checksummed migrations under the existing PostgreSQL advisory transaction lock. Historical payloads remain available through Loki within retention. The event catalog and event-based KPIs cover data indexed after rollout and expose `coverage_start`. [KPI contract](kpi-contract.md)

## Security controls

The backend checks roles on protected routes, validates inputs and request size, uses bound SQL values, and applies an explicit browser origin allowlist. New password hashes use salted PBKDF2-HMAC-SHA256 with 600,000 iterations. PostgreSQL stores session digests, and logout or account changes revoke sessions. The app limits login attempts and retains CSRF protection for cookie-authenticated mutations. Raw event detail is admin-only and opt-in, with recognizable credential patterns redacted. Audit data records operation outcomes and server request IDs without passwords, tokens or incident notes. CSV output neutralizes formula-leading cells. [Security review and role matrix](backend-security-review.md) · [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Test execution

- The regression suite finished with 330 passed, 2 skipped and 1 deselected. This included six Microsoft Edge browser tests and the isolated PostgreSQL and Loki suites. The separate Phase 5 storage integration test passed after enabling its native PostgreSQL and Loki settings, bringing the total to 331 distinct passing tests.
- Ruff lint and format, mypy, Compose configuration validation, and `git diff --check` passed. Pytest reported the existing Starlette TestClient deprecation warning.
- The PostgreSQL and Loki fixture runs exercised a mixed-vendor and a dual-RouterOS outage. Both produced one logical incident, handled delayed and repeated messages across a processor restart, and returned event detail and recovered topology through the REST API.
- PostgreSQL API and correlation tests exercised idempotent migrations, registry uniqueness, unknown sources, replay, concurrent rule thresholds, cross-window interface recovery, RBAC, audit and exports.
- Native Grafana 13.3 loaded all three provisioned dashboards, reported both datasource connections healthy, and returned expected results from all nine KPI panels. A restricted PostgreSQL reader could select KPI views and was denied access to protected tables and writes.
- Docker Compose parsed the checked-in template with `docker compose --env-file .env.example config --quiet`. The Docker daemon was unavailable for a runtime Compose test.
- `pip-audit -r requirements.txt` reported no known vulnerabilities in the pinned Python runtime requirements at verification time.

## Deployment and frontend integration

Use the existing Ubuntu Compose deployment workflow, back up PostgreSQL and the collector and processor volumes, and use the documented readiness checks. Set an explicit frontend origin and a browser-facing Grafana URL. Provision the Grafana PostgreSQL datasource using a dedicated reader with view-only grants. For HTTPS access, set the trusted hosts and secure cookie option at the reverse-proxy boundary. [Deployment](deployment.md) · [Grafana integration](grafana-integration.md)

The frontend can call JSON login, keep the bearer token in memory, and send `Authorization: Bearer <token>` until expiry or logout. Use `GET /auth/me` to discover the role and always handle API `401` and `403` responses. The integration guide includes concrete requests and response shapes. [Frontend integration](frontend-integration.md)

## Remaining issues and live validation

- **Live GNS3 and Compose runtime blocked.** This workstation had no local GNS3 and rsyslog listeners and the Docker Linux daemon was unavailable. The live Ubuntu endpoint and confirmed RouterOS endpoint inventory were unavailable. The evidence record lists passive checks and the eight operator scenarios. [GNS3 evidence](evidence/gns3-validation/README.md)
- **Telemetry-dependent rules.** Device restart, generic network errors and dedicated port flap incidents need verified parser inputs. Interface state and OSPF already have verified inputs. Registered expected logging intervals yield active, stale or unknown activity. An independent collector-health and heartbeat policy is needed before stale logging becomes an automatic inactivity incident.
- **Historical and availability metrics.** Event KPIs cover the new catalog. Existing Loki queries remain available for older retained events. Syslog transitions alone provide insufficient coverage for an availability percentage.

## Acceptance matrix

| Priority | Feature | Initial status | Final status | Implementation evidence | Test evidence | Remaining limitations |
|---|---|---|---|---|---|---|
| P0 | Dashboard summary | PARTIAL | COMPLETE | `app/storage/backend.py`, `GET /dashboard/summary` | Filtered PostgreSQL dataset and both processor fixtures | Catalog coverage starts at rollout. |
| P0 | Event details | PARTIAL | COMPLETE | Catalog, Loki lookup, related-incident references and admin raw opt-in | PostgreSQL API and native Loki pipeline | Older Loki events use a bounded lookup window. |
| P0 | OSPF link mapping | PARTIAL | PARTIAL | Configurable scoped endpoint IDs, observation projection, collector address pinning | Native PostgreSQL and Loki verified mixed-vendor and dual-CHR fixture behavior | Confirm and configure actual lab endpoints. |
| P0 | Network topology | MISSING | COMPLETE | `app/services/topology.py`, `config/topology.yaml`, topology routes | Unknown, configured and observed graph states plus fixture recovery | Physical inventory requires operator configuration. |
| P0 | Live GNS3 syslog | BLOCKED | BLOCKED | Existing rsyslog and processor stack, operator verification guide | Fixture pipeline and collector tests are recorded separately | Live GNS3/Ubuntu and Compose daemon unavailable. |
| P1 | PostgreSQL device registry | MISSING | COMPLETE | Migration 006, source registry, stable UUID and nullable attribution | Native PostgreSQL migrations, duplicate and source isolation tests | Pre-catalog device associations are unknown. |
| P1 | Device API | MISSING | COMPLETE | Device CRUD, soft deactivation, event and incident history | PostgreSQL API tests and authorization checks | Registration reflects observed logging, not reachability. |
| P1 | Correlation rules expansion | PARTIAL | PARTIAL | Managed rules plus existing OSPF and interface lifecycle | Native PostgreSQL concurrent thresholds, restart, recovery and operator override | Device restart, generic errors, port flap and automatic inactivity require verified telemetry. |
| P1 | Rule management | MISSING | COMPLETE | Rule CRUD, activation checks, revisions and isolated simulation | PostgreSQL API and simulation tests | Existing YAML built-ins are configuration-owned. |
| P1 | Frontend authentication | PARTIAL | COMPLETE | Bearer login, logout, identity lookup and revocation | CORS, throttling, session and role tests | Parallel legacy cookie login remains supported. |
| P1 | Grafana deep linking | PARTIAL | COMPLETE | Configurable UID and browser URL, filtered variables, read-only datasource | URL tests and native Grafana query verification | Operator must provision the datasource in the lab. |
| P1 | Unified KPI contract | MISSING | COMPLETE | Shared facts, API summary, Grafana dashboard and `docs/kpi-contract.md` | PostgreSQL parity and nine Grafana query results | Availability stays unknown without continuous telemetry. |
| P2 | RBAC | MISSING | COMPLETE | ADMIN, ANALYST and VIEWER permissions and account administration | Positive and negative API tests | Grafana uses its own account permissions. |
| P2 | Application audit | PARTIAL | COMPLETE | Append-only API read access, transaction-coupled mutation audit | Login, logout, role, device, report and incident auditing tests | Legacy SQLite demo has no PostgreSQL audit store. |
| P2 | Reporting | PARTIAL | COMPLETE | Period-based JSON/CSV, summary, event, incident and device activity | PostgreSQL API, KPI equality and CSV protection tests | Exports enforce a row cap and indicate truncation. |
