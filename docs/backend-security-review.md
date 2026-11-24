# Backend security review

The operational API authorizes by role on the server. All authenticated roles share the same configured lab inventory. Management IP addresses, event payloads, administrative changes, and audit records have the additional restrictions below.

## Role matrix

| Capability | Viewer | Analyst | Admin |
|---|---|---|---|
| Sign in, inspect own session, sign out | Yes | Yes | Yes |
| Read storage readiness, dashboard summary, topology and Grafana link | Yes | Yes | Yes |
| See management addresses and individual significant events | | Yes | Yes |
| Read event catalog, event detail and related evidence | | Yes | Yes |
| Read redacted raw event text on explicit detail request | | | Yes |
| Read incidents and evidence | | Yes | Yes |
| Acknowledge or resolve incidents | | Yes | Yes |
| Reopen an incident | | | Yes |
| Read registry and device activity | | Yes | Yes |
| Create, update or deactivate devices | | | Yes |
| Read, test or manage rules | | | Yes |
| Read and export summary reports | Yes | Yes | Yes |
| Read and export detail reports | | Yes | Yes |
| Read application audit logs | | | Yes |
| Create users, update passwords or roles, and revoke access | | | Yes |

The configured bootstrap account also serves the legacy Jinja dashboard. Managed accounts authenticate through the JSON API. Grafana authenticates separately. Its access policy must match the readers authorized to see the lab's metrics and any Loki data sources shared in the same Grafana organization. See the [Grafana integration guide](grafana-integration.md).

## Verified controls and operational boundaries

| Area | Control | Verification |
|---|---|---|
| Authentication | New password hashes use PBKDF2-HMAC-SHA256 with 600,000 iterations. Existing hashes retain verification using their encoded parameters. Bearer tokens are random and stored only as hashes with expiry. Managed role, enabled-state or password changes revoke sessions. Sign-out revokes the current bearer session. | Integration suite covers login, revocation, role change and restart. Rotate the session secret or configured password hash to invalidate bootstrap bearer sessions. |
| Abuse prevention | Shared in-process login throttle bounds expensive password checks and returns 429. The body middleware limits versioned API mutations to 4 MiB and legacy form mutations to 16 KiB. | The contract tests cover the source throttle and oversized request. Enforce shared limits at an approved proxy if scaling beyond one process. |
| Browser boundaries | Explicit CORS origins, browser CSRF on cookie-based mutations, trusted hosts in production, security response headers, and `Cache-Control: no-store` for API responses. | Existing auth tests and new authorization integration tests cover cookie and bearer entry points. |
| Data minimization | The catalog stores a redacted display message plus indexes and references. Viewer topology omits management IPs. Bearer event lists restrict raw text and detail exposes redacted raw evidence only with Admin access. | Integration suite exercises Viewer and Analyst access, including denied raw evidence. |
| SQL and rule validation | API request models constrain identifiers and rule values. SQL binds request values. Managed rules accept only declarative, allowlisted definitions. | Integration suite covers invalid and conflicting mutations and rule test isolation. |
| Export handling | Exports enforce role and row limits. CSV text beginning with spreadsheet formula markers is prefixed to force text interpretation. | Reporting integration uses a formula-like event message and checks both truncation and redaction. |
| Audit | Authentication attempts, logout, user/device/rule changes, operator incident transitions and generated reports create append-only API audit records with an application request ID when present. Password change records identify the actor and user without recording credentials or hashes. | Integration suite checks record visibility, request IDs and operator incident changes. |
| Dependencies | Production Python pins were checked with `pip-audit -r requirements.txt`. | No known vulnerabilities reported at the time of the audit. See [acceptance evidence](backend-final-report.md). |

Use TLS on any network path carrying credentials or session tokens, and keep Loki and PostgreSQL off public listeners. Keep original raw logs in a controlled spool. Pattern-based redaction covers recognized credential formats. The collector relies on source-network controls for source-address attribution, particularly for RouterOS UDP traffic.

New PBKDF2-HMAC-SHA256 hashes use the iteration count in the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Audit history is append-only through the application API. PostgreSQL owners retain administrative ability to modify the database, so enforce retention, backups, and audit-table access at deployment. Arrange isolated integration first if changing network exposure, adding a proxy, or installing a Grafana database role.
