# Backend implementation plan

Reuse the parsers, Loki payloads, PostgreSQL incident lifecycle, and the worker's durable checkpoint. Add one PostgreSQL row per distinct event for lookup, registry attribution and KPIs. Keep the original syslog in the collector spool and the existing normalized payload in Loki. An unmatched address stays unregistered. Use only operator-confirmed adjacency configuration for mapped links.

1. Add the metadata migration and worker integration. Verify replay, unknown sources, event retrieval and topology through the existing API process.
2. Add device and rule administration, frontend authentication and Grafana linking. Verify migration upgrade, authorization, deterministic rule evaluation and one KPI definition for both dashboards.
3. Apply role permissions, mutation audit records and bounded reports. Verify forbidden access, revocation, incident history and CSV escaping.
4. Run available regression and infrastructure tests. Record fixture, disposable-service and live evidence independently in the acceptance report.

Acceptance requires passing automated checks, documented query semantics and a specific evidence path for each feature. Lab topology, network interfaces, deployments and persistent service configuration require the existing operator workflow.
