# Backend audit

Baseline `94ec35d` on `main`, with existing working-tree edits in the processor, Loki adapter, Compose, deployment notes and tests. The local repository is the implementation source. PostgreSQL migrations 001–005 and Loki already support operational incident state and searchable normalized logs. The legacy Jinja workflow uses SQLite and a signed administrator cookie. No populated environment file was read.

| Priority | Requested feature | Initial status | Repository evidence |
|---|---|---|---|
| P0 | Dashboard summary | PARTIAL | `app/web/routes.py` builds HTML operational metrics with `app/storage/postgres.py`. The JSON router has no consolidated summary. |
| P0 | Event details | PARTIAL | `app/web/api.py` lists Loki events with a cursor. No detail lookup or reverse incident lookup. |
| P0 | OSPF link mapping | PARTIAL | `app/services/ospf_correlation.py` deduplicates mapped bilateral failures and applies per-reporter recovery. `config/correlation_rules.yaml` has no confirmed links. No current link-state API. |
| P0 | Topology | MISSING | GNS3 design and older physical inventory are documented. The JSON router has no topology graph. |
| P0 | Live GNS3 validation | BLOCKED | Prior acceptance notes describe fixture evidence. This workstation has no local listener on 3080 or 5514 and Docker Desktop's Linux daemon is unavailable. |
| P1 | PostgreSQL device registry | MISSING | Migrations 001–005 cover aggregates, evidence, lifecycle and notification delivery. |
| P1 | Device API | MISSING | Legacy HTML `/devices` is derived from SQLite. No registry management routes. |
| P1 | Correlation expansion | PARTIAL | The worker applies the built-in interface and OSPF rules. Parser fixtures cover several additional types. The silent-device service belongs to the legacy dashboard and is not a registered heartbeat source. |
| P1 | Rule API | MISSING | Static validated YAML in `app/schemas/correlation.py` and a read-only rules catalog. |
| P1 | Frontend authentication | PARTIAL | PBKDF2, signed cookies, CSRF and authenticated legacy JSON endpoints exist. No JSON login or server-side API session lifecycle. |
| P1 | Grafana linking | PARTIAL | Loki datasource and dashboards `network-event-operations` and `network-ospf-observability` are provisioned. Only the former has severity, event-type and device variables. |
| P1 | Unified KPI contract | MISSING | Grafana LogQL counts entries and the HTML dashboard uses separate aggregations. Neither establishes cross-dashboard replay semantics. |
| P2 | RBAC | MISSING | Existing web authentication supports a single configured administrator. |
| P2 | Application audit | PARTIAL | Migration 003 records incident status history. It does not record authentication or other administrative activity. |
| P2 | Reporting | PARTIAL | HTML alert/scenario CSV exports exist. No versioned recurring-period reporting or shared KPI calculation. |

The system Python lacked Pytest. The repository virtual environment ran the baseline suite. Final test counts and infrastructure availability are recorded in [backend progress](backend-progress.md).
