# Frontend integration

> This guide records the separate frontend contract at `5527465`. For Grafana-only, use the current [operational API](api-contract.md) and [Grafana setup](grafana-integration.md).

The separate dashboard uses the versioned JSON API under `/api/v1`. The built-in Jinja dashboard keeps its same-origin session-cookie workflow. See the [API reference](api-contract.md).

## Configure the frontend

Set the frontend's public API origin for its own build and include the frontend's exact origin in the backend's `FRONTEND_ORIGINS`. A development example is a frontend at `http://localhost:5173` with `FRONTEND_ORIGINS=http://localhost:5173` and an API at `http://localhost:8000/api/v1`. Production browser origins use HTTPS and list the public host in the backend's `TRUSTED_HOSTS` where applicable. An origin includes scheme, hostname and optional port, without a trailing slash or path.

The backend allows cross-origin `Authorization` and `Content-Type` headers and exposes `X-Request-ID`, `Retry-After`, `Content-Disposition`, and `X-Report-Truncated`. Browser requests from the separate frontend use `credentials: "omit"`.

## Sign in and call the API

```ts
const apiBase = "http://localhost:8000/api/v1"; // Set from your frontend environment.

async function signIn(username: string, password: string) {
  const response = await fetch(`${apiBase}/auth/login`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw response;
  return response.json() as Promise<{
    access_token: string;
    token_type: "bearer";
    expires_at: string;
    user: { username: string; role: "admin" | "analyst" | "viewer" };
  }>;
}

async function authorized(path: string, token: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${apiBase}${path}`, { ...options, headers, credentials: "omit" });
}
```

Keep the bearer token in memory, clear it on sign-out, and use a fresh sign-in after a page reload. The backend stores only the token hash and expires the session after `API_SESSION_SECONDS` (3,600 by default, configurable from 300 to 28,800). Sign in again after expiry. Call `GET /auth/me` to check the current role. `POST /auth/logout` revokes that session and responds with 204. Changing a managed account's role, enabled state, or password revokes all of its sessions. Rotating the configured session secret or bootstrap password hash revokes bootstrap bearer sessions.

- For 401, clear authentication state and offer sign-in.
- For 403, keep the session and explain the permission restriction.
- For 429, use `Retry-After` to suspend login retries.
- For 422, show the relevant validation error. For 502 or 503, show any remaining data and a retry action.
- Include `X-Request-ID` in troubleshooting messages. Treat passwords, tokens and raw evidence as sensitive and exclude them from client logs.

## Render operational data

Use `GET /dashboard/summary` for KPI cards and `GET /topology` for the current graph. Render an empty series separately from an unavailable payload. If `truncated=true`, indicate that the topology displayed covers a bounded subset. Preserve an unmapped link's null target. Viewer accounts receive summary counts and topology with management IPs omitted.

Use the catalog envelope to list events and the event ID to request detail or related evidence.

```ts
const params = new URLSearchParams({
  start: "2026-11-24T00:00:00Z",
  end: "2026-11-25T00:00:00Z",
  category: "routing",
  page: "1",
  page_size: "50",
  sort: "desc",
});
const catalog = await authorized(`/events/catalog?${params}`, token);
const detail = await authorized(`/events/${encodeURIComponent(eventId)}`, token);
const related = await authorized(`/events/${encodeURIComponent(eventId)}/related`, token);
```

Catalog requests use a fixed time window across pages. The legacy cursor endpoint can still search events ingested before the catalog was added. A detail can expose its indexed metadata while the Loki payload is unavailable. An administrator can request redacted raw evidence using `include_raw=true` on detail. Render event text and notes as text.

Use the existing `/alerts` routes for incident history, acknowledgement, and resolution. Open Grafana from `GET /grafana/link` with the same range and supported filters. Open the returned `url` in a separate tab so Grafana can authenticate the operator independently.

## Download a report

```ts
const response = await authorized(
  "/reports/export?report=incidents&format=csv&period=weekly&limit=500",
  token,
);
if (!response.ok) throw response;
const download = await response.blob();
const truncated = response.headers.get("X-Report-Truncated") === "true";
// Save the Blob as networksec-incidents.csv and surface truncation in the UI.
```

Exporting registers a report operation in the application audit log. Viewer accounts can export only summaries. Use the [KPI contract](kpi-contract.md) for calendar labels, missing values and device status.
