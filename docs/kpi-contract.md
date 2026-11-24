# Network Event KPI contract 1.0

The operational API uses PostgreSQL's unique event catalog and incident lifecycle. Grafana's **Network Event KPIs** dashboard reads restricted PostgreSQL views over the same facts. Loki dashboards continue to display the original technical log stream, including observations outside PostgreSQL catalog coverage.

## Window and identity

- `[start, end)` is a half-open UTC interval. API inputs are RFC 3339 timestamps with offsets. Daily, weekly, and monthly presets are trailing 1, 7, and 30 days. Custom windows are at most 90 days. Match the same millisecond-aligned boundaries in Grafana and API comparisons.
- Each event counts once by `event_id`, including when the same event is replayed. `event_timestamp` describes when it happened, `received_at` when rsyslog received it, and `ingested_at` when its first durable catalog row was written. Two different observations of a shared OSPF outage can both count as events and contribute to one incident.
- Incident identity is `aggregate_id`. Current metrics exclude superseded OSPF incidents and newly tracked interface-up-only aggregates. An incident can link to multiple events and devices. It counts once in each filtered selection.
- PostgreSQL only covers events written by the upgraded processor. `coverage_start` is the earliest ingest timestamp present in the catalog and is independent of selected filters. A zero result outside coverage means zero matching rows in the catalog. Use Loki for retained, older payloads.

## Metrics

| API identifier | Display and unit | Calculation, time basis and missing values |
|---|---|---|
| `total_events` | Total events | Count distinct catalog events by event time. Zero if no rows match. |
| `by_severity.critical`, `by_severity.high` | Critical events, high events | Each counts events of exactly that severity within the event-time window. Missing keys represent zero. |
| `by_category` | Events by category | Count events by normalized category within the event-time window. Missing keys represent zero. |
| `by_source` | Events by reported device | Group by reported device name. Missing names use `(unknown)`. Keep the top 100 names and combine the remainder in `(other sources)`. |
| `trend` | Event volume | Count by event time in UTC buckets. Bucket width is one hour for windows up to 72 hours and one day for longer windows. Missing buckets have no matching rows. |
| `ingestion_trend` | Ingestion volume | Same buckets using the first catalog commit timestamp. |
| `events_per_second` | Mean ingestion rate, events/s | Count first ingestions in the window divided by the window length in seconds. Zero if no rows match. |
| `last_ingested_at` | Most recent successful catalog ingest | Maximum first-ingest time across the catalog after applying non-time filters, or null if there are no matching ingestions. It is independent of the selected event range. |
| `active_incidents` | Active incidents | Incidents in a current non-resolved state and first seen before `end`. Includes older still-open incidents. |
| `resolved_incidents` | Resolved incidents | Current resolved incidents whose final status-change time is inside the window and whose first observation precedes `end`. |
| `critical_incidents`, `high_incidents` | Critical incidents, high incidents | Counts at exact severity of the union of the active and resolved populations defined above. |
| `mean_resolution_seconds` | Mean resolution time, seconds | Mean final status-change time minus first observation among counted resolutions. Excludes negative durations. Null if there are no eligible resolutions. |
| `registered_devices` | Registered devices | Count current registry IDs, including disabled devices. Uses device UUID or registry name if filtered. |
| `device_status.active` | Recently observed devices | Currently enabled with a known `last_seen` inside its configured expected interval. Status reflects observed logging. |
| `device_status.unknown` | Devices with unknown status | Currently enabled without a known observation or configured expectation. An enabled device observed outside its expected interval is `stale`. Deactivated entries are `disabled`. |
| `links` | Current OSPF link evidence | Displays current configured or observed OSPF adjacency status. Unmapped neighbors remain unknown with no target. |
| `link_availability` | OSPF link availability percentage | Null. A measured denominator requires interval coverage and evidence of link health during gaps. |
| `significant_events` | Recent critical/high events | Up to ten matching events, newest first by event time then ID. Viewer responses omit event-level records. |

## Filtering and interoperability

Catalog filtering is by stable device UUID, exact reported device name, severity, normalized category, event type, vendor, and literal substring of the redacted message. Supplying both a device ID and name applies both filters. Device UUID reflects immutable attribution at the first ingest. Registry name filtering is case-insensitive and the registry uses current state. Incident severity is the incident's own severity. Incident device filters match associated events or the incident's recorded device name where applicable. Incident category is derived from its event types. Topology link lists use current evidence and are narrowed by selected endpoint.

The category map groups link events and port flaps under `interface`, OSPF transitions under `routing`, login failures under `authentication`, ACL denies under `firewall`, configuration changes under `configuration`, and port security violations under `security`.

Grafana's event panels match the API metric definitions when both use the same device UUID or reported name, severity, category, time window, and event population. Grafana can additionally constrain event panels to an incident's current evidence. Consult the panel description for supported filters, especially device and incident panels. Event type, vendor and message search are API-only filters. See the [Grafana integration guide](grafana-integration.md).

`/reports/summary` uses the dashboard summary query. Detail reports and exports use the corresponding event, incident and device selections. Incident detail reports list windows overlapping the requested time. Device activity reports count events within the selected period per registered device and include the first and last matching event times.

The PostgreSQL integration suite compares the API summary to all nine shipped Grafana panels using the same fixture window and filters. A disposable native Grafana 13.3.0 check executed all nine panel queries through Grafana, checked both datasources and verified the restricted reader grants. Browser dashboard rendering and Docker Compose runtime were outside that check. See [backend acceptance](backend-final-report.md) for execution evidence.
