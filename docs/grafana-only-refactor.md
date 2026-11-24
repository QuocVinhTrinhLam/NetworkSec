# Grafana-only refactor

The comparison baseline is `55274650958efef75b65c147d8b85abc86cd21c6`. Local and remote `main` and `grafana-only` pointed to that commit when work began. The initial working tree had only the existing untracked `.vscode/` directory. The implementation is an uncommitted working-tree change on `grafana-only`.

## Inventory

Source counts cover physical lines, including comments and blanks. Minified assets count by stored lines. The baseline source manifest is available from `git ls-tree -r --name-only 5527465 -- app tests scripts infra`. Baseline dependency pins, route definitions and dashboard assets are available from the same commit.

| Measure | `5527465` | Grafana-only |
| --- | ---: | ---: |
| Application Python files and lines | 72 / 13,483 | 71 / 12,704 |
| Test Python files and lines, including helpers | 45 / 9,267 | 42 / 7,990 |
| Script Python files and lines | 2 / 83 | 2 / 83 |
| Custom Dashboard templates and lines | 11 / 841 | 0 / 0 |
| Custom Dashboard static files and lines | 5 / 1,085 | 0 / 0 |
| Provisioned Grafana dashboards | 3 | 4 |
| Pinned runtime Python dependencies | 34 | 30 |
| Additional pinned development dependencies | 7 | 6 |
| Versioned OpenAPI paths and operations | 35 / 42 | 34 / 41 |
| Compose services across all profiles | 9 | 9 |
| Compose named volumes | 7 | 7 |
| Pytest cases collected | 337 | 323 |

The baseline services were `postgres`, `loki`, `grafana`, `rsyslog`, `dashboard`, `processor`, `bot`, `mock` and `syslog-generator`. The headless `api` service takes the place of `dashboard`. `grafana-data`, `loki-data`, `monitor-data`, `postgres-data`, `processor-state`, `syslog-queue` and `syslog-raw` retain their names.

## Dependency findings and administration

| Baseline dependency | Refactor decision |
| --- | --- |
| Jinja templates, local JavaScript and CSS, form handling and signed dashboard cookies | These serve the retired HTML routes. Remove the assets, the router, and runtime pins for Jinja2, MarkupSafe, python-multipart and itsdangerous. Remove the development Playwright pin with the Jinja browser suite. |
| FastAPI, Uvicorn and PostgreSQL accounts | These serve the operational API and its authentication and authorization. Retain the JSON API, revocable bearer sessions, RBAC, login throttling, size limits, sanitized validation errors, security headers and CSV formula protection. Existing bearer tokens continue to work until expiry or revocation under the same configuration. |
| SQLite and `monitor-data` | The bot and mock CLI use the existing SQLite database. Preserve both consumers and their mount. The processor maintains its own SQLite checkpoint and correlation journal in `processor-state`. The API no longer mounts `monitor-data`. |
| Telegram notification links and outboxes | Point PostgreSQL-backed messages to the provisioned Grafana incident dashboard. Preserve the send/edit, retry, deduplication and lifecycle logic. Legacy SQLite callbacks continue to work in Telegram. |
| Built-in correlation, configured physical topology and OSPF mapping | Retain and validate the existing YAML through the application models. The API still builds the full graph, including configured links and unmapped peers. Grafana shows mapped and unmapped observations by endpoint. |
| Device, managed rule and API user writes | The processor consumes database-managed device identity and rule definitions. Keep their existing validated, transactional and audited APIs, along with API user and incident administration. Replacing these writes with YAML or a direct database CLI would require equivalent validation, revision and attribution behavior. |

`GET /api/v1/reports/summary` already called the same implementation as `/api/v1/dashboard/summary`; use the reports path. A structural comparison of the generated OpenAPI documents found only the removed route and updated `403` descriptions. Health remains available at `/health`. Grafana uses Loki for technical logs and restricted PostgreSQL views for KPIs, incident status, history and OSPF endpoint evidence. The additional views ship in migration `010`. [API contract](api-contract.md) · [Grafana setup](grafana-integration.md) · [Upgrade and rollback](deployment.md#nâng-cấp-grafana-only).

## Verification

- The independent baseline audit reports 335 distinct passes across its runs. The local baseline run recorded 293 passes, 37 skips and 7 deselections under the standard fast command.
- The Grafana-only fast run recorded 285 passes, 37 skips and 1 deselection. Ruff lint and format, mypy, OpenAPI regeneration and Compose validation with all profiles passed. The retained entry points passed an import and API smoke check with the retired Python packages blocked.
- The suite with disposable PostgreSQL 17 and Loki 3.7 recorded 321 passes, 1 skip for the Compose restart test, and 1 deselection for the rsyslog integration test. It exercised storage, migration replay, mixed-vendor and dual-RouterOS OSPF lifecycle, the Grafana views, notification delivery with fake gateways, API roles and audit behavior. TestClient emitted the same Starlette `httpx` deprecation warning as the baseline.
- Native Grafana 13.3 loaded all four dashboards. Both data sources passed their health checks. The three new panels executed through Grafana using the restricted role. A browser displayed the fixture incident and its history after opening the Telegram-format link and selecting its ID in the queue.
- The Docker engine was stopped. Runtime Compose, the container rsyslog TCP/UDP test, the container restart test and live GNS3 acceptance remain unverified for this working tree. The existing GitHub Actions workflow definitions remain byte-for-byte equivalent to the baseline.

Local and remote `main`, remote `grafana-only`, and local `HEAD` still resolve to `5527465`. Migrations `001`–`009` and the GNS3 files match the baseline. The refactor leaves the existing volumes and `.vscode/` in place.
