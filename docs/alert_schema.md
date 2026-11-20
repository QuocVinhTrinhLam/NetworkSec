# Alert Schema v1

`app.schemas.alert.Alert` is the single validated contract shared by ingestion,
SQLite storage, the dashboard, and Telegram notifications. Inputs are treated as
untrusted data. Pydantic rejects unknown fields, validates network values, bounds
text fields, and truncates `raw_log` to `RAW_LOG_MAX_LENGTH` (4096 by default).

## Identity and deduplication

- `alert_id` is SHA-256 over `source`, `rule.id`, `device.name`, `network.src_ip`,
  and the event timestamp rounded down to one second. Replaying the same event is
  therefore idempotent.
- `dedup_key` is SHA-256 over `rule.id`, `device.name`, and `network.src_ip`. The
  notification worker uses it to aggregate related events inside its time window.

The one-second identity bucket is intentionally narrower than the Telegram dedup
window: distinct events remain available for investigation while their notification
can still be summarized.

## Fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | literal `"1.0"` | Contract version |
| `alert_id` | string | Derived; caller values are ignored |
| `timestamp` | UTC datetime | Event time; timezone is required |
| `received_at` | UTC datetime | Ingestion time |
| `source` | `mock` | Legacy demonstration adapter source |
| `device` | object | Name, type, optional vendor and validated IP |
| `severity` | enum | Low, medium, high, or critical |
| `rule` | object | Rule ID, description, level, groups, catalog link |
| `network` | object | Optional validated IPs, ports, protocol, interface, VLAN |
| `user` | string or null | Account involved |
| `mitre` | array | ATT&CK technique ID, name, and tactic |
| `event_count` | integer | At least 1 |
| `status` | enum | New, acknowledged, or muted |
| `acknowledged_by` | string or null | Analyst identity |
| `acknowledged_at` | UTC datetime or null | Acknowledgement time |
| `tags` | string array | Searchable normalized labels |
| `raw_log` | string | Hostile source text; bounded before storage |
| `dedup_key` | string | Derived aggregation fingerprint |

The machine-readable contract is exported to [`alert.schema.json`](alert.schema.json).

## Compatibility migration

`Database.initialize()` adds missing v1 columns to an existing flat SQLite alerts
table and backfills `received_at`, `status`, MITRE JSON, and `dedup_key`. Existing
primary keys remain addressable so old dashboard links keep working. New writes use
the deterministic v1 `alert_id`.
