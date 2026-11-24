# Frontend readiness checklist

> This checklist records the frontend handoff at `5527465`. The current integration contract is in the [operational API reference](api-contract.md).

**Verdict · PARTIAL.** The versioned contract is ready for client implementation against the checked-in OpenAPI 3.1 snapshot. This workspace contains the server-rendered dashboard. The separate dashboard was unavailable for end-to-end verification.

- [x] Use the generated OpenAPI spec for all 42 versioned operations. Regenerate with `python -m scripts.export_openapi` from the repository root. The audit test compares the snapshot to the actual route declarations. Production serves neither Swagger UI nor the OpenAPI route. [OpenAPI spec](openapi.json)
- [x] JSON login, identity, logout and role guards ran against disposable PostgreSQL. The bearer client should use `Authorization: Bearer <token>`, keep the token in memory, omit cookie credentials for cross-origin requests and clear the token on logout or 401. A legacy administrator session is accepted only when no Authorization header is supplied. Legacy cookie mutations require CSRF.
- [x] Validate errors using `detail` as a string or, on 422, a list of issues. Preserve `X-Request-ID` for support, use `Retry-After` on 429, and distinguish a dependency failure from degraded storage health in a successful response.
- [x] Use `/events/catalog` for numbered pages. Keep UTC boundaries and filters fixed when paging, and use `/events` cursor mode for older Loki data. Treat legacy `raw_message` as a restricted placeholder. Use the selected event’s timestamp for a historical Loki lookup, and render `payload_status=unavailable` separately from 404.
- [x] Use `/dashboard/summary` and `/reports/summary` for the shared KPI contract. Display `coverage_start`, unknown link states and missing availability explicitly. Represent `registered_devices` and observed device activity as separate metrics. Viewers receive aggregate summaries and topology, while analysts and admins can access investigation data.
- [x] Check `Content-Type`, `Content-Disposition` and `X-Report-Truncated` on downloads. The limit is 1,000 rows. For device reports, retain `enabled` when switching between JSON pages and downloads. Device identifiers are registry UUIDs, while topology node IDs also include inventory or observation identifiers.
- [x] Use the server-returned Grafana URL as a navigation link. Grafana runs its own authorization. Match UTC windows and supported filter scopes when comparing metrics. [KPI contract](kpi-contract.md) · [API contract](api-contract.md)
- [ ] Run the actual separate frontend origin against the deployed API over HTTPS. Confirm preflight, login, logout, 401 and 403 handling, expired sessions, role-specific menus and authenticated CSV download.
- [ ] Verify deep links, topology, stale and unknown states, mobile layouts and frontend empty/degraded UI with confirmed lab data. Compare one fixed event and one incident through the frontend, API and Grafana.

The six Microsoft Edge E2E tests exercise the existing dashboard. The API and native storage tests exercise the frontend-facing contract in isolation. [Independent audit](independent-backend-audit.md) · [Frontend integration guide](frontend-integration.md)
