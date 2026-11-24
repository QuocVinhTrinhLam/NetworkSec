# Operational API v1

Routes below use the `/api/v1` prefix. Local development serves `/openapi.json`. Use the generated specification for production integrations. The original cursor-based events API remains available. [OpenAPI specification](openapi.json) · [Cursor API details](api.md)

## Authentication and errors

Send `Authorization: Bearer <access_token>` after calling `POST /api/v1/auth/login`. The API authenticates only explicit bearer headers and checks roles on the server. Existing unexpired bearer sessions carry forward with the same PostgreSQL database and bootstrap configuration. Grafana uses its own sign-in and read-only datasources. [Grafana integration](grafana-integration.md).

Clients of `/api/v1/dashboard/summary` must switch to `GET /api/v1/reports/summary`, which accepts the same filters and returns the same schema. Clients using the Custom Dashboard's HTML paths or signed cookies must migrate to Grafana or bearer-authenticated API calls.

The normal error shape is `{"detail":"message"}`. Schema validation returns 422 and may use an array of `loc`, `type`, and `msg` entries. Use the response's `X-Request-ID` when reporting an error. API responses carry `Cache-Control: no-store`.

| Status | Client handling |
|---|---|
| 400 | Reset an invalid Loki cursor and request the first page. |
| 401 | Sign in again. Invalid credentials and expired, revoked or absent sessions fail authentication. |
| 403 | The account lacks the required role. |
| 404 | The requested resource is absent in the selected scope or, for legacy events, the selected time window. |
| 409 | The user, device identity or rule conflicts with an existing resource or built-in rule policy. |
| 413 | Reduce the request body. Versioned API mutations accept up to 4 MiB. |
| 422 | Correct the request schema, enum, identifier, time window, or pagination. |
| 429 | Honor `Retry-After` before another sign-in attempt. |
| 502 or 503 | Report a dependency error and retry with bounded backoff. A Grafana link also returns 503 if disabled or misconfigured. |

## Time, filters, and pages

- Use RFC 3339 dates with an explicit UTC offset, such as `2026-11-24T00:00:00Z`. Event catalog and reporting windows are half-open `[start, end)` and at most 90 days. By default the end is now. `period=daily|weekly|monthly` supplies a rolling 1-, 7-, or 30-day window when `start` is omitted. `period=custom` requires both boundaries.
- Catalog searches accept `device_id` (UUID), `device_name` (reported name, exact), `severity`, `category`, `event_type`, `vendor` and literal case-insensitive `search` over the redacted indexed message. The [metric contract](kpi-contract.md) lists category and cross-resource filter behavior.
- Catalog, devices, audit and report pages use `page` 1–1,000 and `page_size` 1–200 unless stated otherwise. Their envelope is `{items, page, page_size, total}`. Catalog events support `sort=asc|desc` using event timestamp then event ID. Resend fixed range boundaries and filters when paging.
- Legacy event pages use an opaque `cursor`, returned as `next_cursor`. The old event envelope has `schema_version`, `items`, `page_size` and `next_cursor`. Its `raw_message` field carries the `[restricted]` placeholder and the event ID remains stable. Use `include_raw=true` on admin event detail when evidence is needed. Keep cursor and number-based paging independent.

## Sessions and users

| Method and route | Role | Request | Success |
|---|---|---|---|
| POST `/auth/login` | Public | `{username,password}` | `200 {access_token,token_type:"bearer",expires_at,user:{username,role}}` |
| GET `/auth/me` | Any | | `200 {username,role}` |
| POST `/auth/logout` | Any | | `204`, session revoked |
| GET `/users` | Admin | Page controls | `200 UserRecord[]` |
| POST `/users` | Admin | `{username,password,role}` | `201 UserRecord` |
| PATCH `/users/{username}` | Admin | At least one of `role`, `enabled`, and `password` | `200 UserRecord`. An effective account change revokes all sessions. |

`UserRecord` contains `username`, `role` and `enabled`. Roles are `admin`, `analyst` and `viewer`. New account passwords are 12–1,024 characters. The configured bootstrap administrator is managed through deployment settings.

## Events, incidents, and topology

| Method and route | Role | Request | Success |
|---|---|---|---|
| GET `/storage/health` | Any | | `200 {status,loki,postgres}`. Check `status` for degradation. |
| GET `/events/catalog` | Analyst, Admin | Catalog filters, sort, page | `200 Page<IndexedEvent>` |
| GET `/events` | Analyst, Admin | Legacy cursor query, or `view=catalog` plus catalog filters, sort, and page | `200 EventPageResponse` or `200 Page<IndexedEvent>` |
| GET `/events/{event_id}` | Analyst, Admin | Optional legacy lookup time window. Admin may add `include_raw=true` | `200 EventDetail` |
| GET `/events/{event_id}/related` | Analyst, Admin | Legacy lookup time window, `limit` 1–200 (default 50) | `200 {incident_ids,related_event_ids}` |
| GET `/alerts` | Analyst, Admin | Time, status, severity, rule ID, event type, device, interface, source IP, search and page | `200 AlertPageResponse` |
| GET `/alerts/{alert_id}` | Analyst, Admin | | `200 AlertRecord` |
| GET `/alerts/{alert_id}/evidence` | Analyst, Admin | | `200 {schema_version,alert_id,event_refs,history,ospf}` |
| POST `/alerts/{alert_id}/acknowledge` | Analyst, Admin | `{note?}` | `200 AlertRecord` |
| PATCH `/alerts/{alert_id}/status` | Analyst, Admin | `{status,note?}` | `200 AlertRecord`. Reopening to `new` requires Admin. |
| GET `/topology` | Any | | `200 {nodes,links,truncated}` |
| GET `/topology/nodes` | Any | | `200 TopologyNode[]` |
| GET `/topology/links` | Any | | `200 TopologyLink[]` |
| GET `/topology/nodes/{device_id}` | Any | Node ID from the graph | `200 TopologyNode` |

Legacy `GET /events` defaults to schema 1.0. Add `include_ospf=true` for both versions. Its page size is 1–500. A catalog filter such as `device_id`, `category`, or `search`, `sort=asc`, or `page>1` also selects the catalog shape. Prefer the explicit catalog route for a predictable response shape. Bearer callers receive the legacy raw-message field as `"[restricted]"`.

`IndexedEvent` has identifiers, three timestamps (`event_timestamp`, `received_at`, `ingested_at`), device information, collector address, parsed source address, vendor, severity, event type, category, parser name, and redacted message. The collector address is the network peer of rsyslog. The source address is extracted from the event body. `device_id=null` means the event was unattributed at ingest.

`EventDetail` contains `event`, `event_id`, `parsing_status`, `correlation_status`, `related_incident_ids`, available protocol `metadata`, optional numeric `facility`, `payload_status`, and optional redacted `raw_message`. If Loki has lost the payload but the catalog row survives, detail returns 200 with `payload_status="unavailable"`. An older Loki-only event may still be located by time range. Its `ingested_at` and device attribution may be null. Original byte evidence is retained in the controlled collector spool. Event and alert IDs are 64 lowercase hexadecimal characters.

`AlertRecord` includes aggregate identity, rule and event family, time window, count, severity, status, and lifecycle actor, timestamp, and note fields. Statuses are `new`, `acknowledged` and `resolved`. Evidence includes the current/historical distinction for OSPF references. An acknowledge request on a resolved alert preserves its resolution.

Topology node IDs may be UUIDs or synthetic graph identifiers. Link kind is `configured`, `observed` or `unmapped`. Current OSPF evidence can yield a status of `up`, `down`, `transitioning` or `unknown`. Unmapped links have no target. Physical and segment links describe operator-supplied inventory. Viewer responses omit management addresses. Use the graph envelope when the client must present the truncation flag.

## Device inventory

| Method and route | Role | Request | Success |
|---|---|---|---|
| GET `/devices` | Analyst, Admin | Page, `enabled`, `search` over name/hostname/location | `200 Page<DeviceRecord>` |
| POST `/devices` | Admin | `DeviceCreate` | `201 DeviceRecord` |
| GET `/devices/{device_id}` | Analyst, Admin | Registry UUID | `200 DeviceRecord` |
| PATCH `/devices/{device_id}` | Admin | Subset of writable fields | `200 DeviceRecord` |
| DELETE `/devices/{device_id}` | Admin | Registry UUID | `204`, device deactivated and historical attribution retained |
| GET `/devices/{device_id}/events` | Analyst, Admin | Event time, severity, category, event type, vendor, search, sort and page | `200 Page<IndexedEvent>` |
| GET `/devices/{device_id}/incidents` | Analyst, Admin | Time, severity, category, page | `200 Page<AlertRecord>` |

This `DeviceCreate` example uses documentation-only IP addresses.

```json
{
  "name": "Lab router A",
  "hostname": "router-a.example.invalid",
  "device_type": "router",
  "vendor": "mikrotik",
  "management_ip": "192.0.2.10",
  "source_addresses": ["192.0.2.11"],
  "expected_interval_seconds": 300,
  "enabled": true
}
```

`DeviceRecord` adds `device_id`, `status`, nullable `last_seen`, `created_at` and `updated_at`. Supply `source_addresses` as the full replacement array when updating it. Reserve the source address and confirm the applicable vendor before promotion. Status `active` or `stale` requires an observation and an expected interval. `unknown` reflects absent evidence or missing policy.

## Correlation rules

All routes require Admin. Built-in rules are identified by `origin="built_in"`. Managed rules contain `id`, `enabled`, `definition` and `revision`. Definitions are declarative JSON.

| Method and route | Request | Success |
|---|---|---|
| GET `/rules` | | `200 RuleRecord[]` with built-in and managed entries |
| POST `/rules` | `{id,enabled?,definition}`. New rules default to disabled. | `201 RuleRecord` |
| GET `/rules/{rule_id}` | | `200 RuleRecord` or built-in rule |
| PATCH `/rules/{rule_id}` | `{enabled?,definition?}`. Supply the full definition to replace it. | `200 RuleRecord` |
| DELETE `/rules/{rule_id}` | | `204`, rule disabled and history retained |
| POST `/rules/{rule_id}/validate` | | `200 {valid,reason}` for compatibility with current configuration |
| POST `/rules/{rule_id}/test` | `{events:[NormalizedEvent,...]}`, up to 100 | `200 RuleOutcome[]` for managed rules or `CorrelationResult[]` for built-in rules |

A managed definition requires `name`, `severity`, `category`, one or more `event_types`, and `group_by`. Optional fields include `description`, `priority`, `vendors`, `recovery_types`, `threshold`, `window_seconds`, and `dedup_seconds`. The allowed group fields are `device_name`, `interface_name`, `source_ip` and `vendor`. Interface event types belong to the enabled built-in interface rule. OSPF transitions belong to the built-in adjacency policy.

Managed rule tests show aggregate ID, matching count, threshold and recovery results. Built-in tests return correlation results from an isolated temporary journal. Production incident state and notifications are outside both test paths. See [rule behavior and deployment](deployment.md#backend-operational-api).

## Reports, audit, and Grafana

| Method and route | Role | Request | Success |
|---|---|---|---|
| GET `/reports/summary` | Any | Summary filters and period | `200 DashboardSummary` |
| GET `/reports/events` | Analyst, Admin | Catalog filters, period, page | `200 Page<IndexedEvent>` |
| GET `/reports/incidents` | Analyst, Admin | Time, severity, category, device, page, `ospf_only` | `200 Page<AlertRecord>` |
| GET `/reports/devices` | Analyst, Admin | Catalog filters for activity, `enabled`, period and page | `200 Page<DeviceActivity>` |
| GET `/reports/export` | Any for summary, Analyst or Admin for details | `report=summary\|events\|incidents\|devices`, `format=json\|csv`, period and corresponding filters, limit 1–1,000 (default 500) | `200` attachment with `X-Report-Truncated` |
| GET `/audit-logs` | Admin | Time, `action`, `actor`, `outcome=success\|failure`, page | `200 Page<AuditRecord>` |
| GET `/grafana/link` | Any | Time, device UUID or name, severity, category, optional `incident_id` | `200 {url}` |

`DeviceActivity` extends `DeviceRecord` with `event_count`, `first_event_at` and `last_event_at`. `AuditRecord` includes timestamps, action, actor, resource, request ID, outcome, and limited structured metadata. The summary view and summary report share the same metric definitions. CSV exports protect spreadsheet formula-like textual values, and display fields from events are redacted. See the [KPI contract](kpi-contract.md).
