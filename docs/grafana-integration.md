# Grafana KPI integration

The existing Compose Grafana service loads **Network Event KPIs** from `infra/grafana/dashboards/network-event-kpis.json`. The dashboard UID is `network-event-kpis`. The existing Loki datasource and event dashboards serve operational log investigation.

## Configure PostgreSQL access

After the backend applies the migrations, connect to the configured database as its owner. The example assumes database `networksec`, schema `public`, and a new dedicated login.

```sql
CREATE ROLE networksec_kpi LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
GRANT CONNECT ON DATABASE networksec TO networksec_kpi;
GRANT USAGE ON SCHEMA public TO networksec_kpi;
GRANT SELECT ON public.kpi_event_facts, public.kpi_device_facts,
    public.kpi_incident_facts, public.kpi_incident_events TO networksec_kpi;
ALTER ROLE networksec_kpi SET default_transaction_read_only = on;
ALTER ROLE networksec_kpi SET statement_timeout = '10s';
```

Set the login password with the PostgreSQL interactive `\password networksec_kpi` command. The Grafana login needs only the listed view privileges. The schema grants expose event timestamps, device attribution and incident status without granting access to raw logs, event messages, user accounts, or audit records.

Create an editable datasource with the supplied JSON sample. Use a local Grafana administrator login. `curl` prompts for the Grafana password.

```sh
curl --fail-with-body --user admin \
  --header 'Content-Type: application/json' \
  --data-binary @infra/grafana/kpi-postgres.datasource.example.json \
  http://127.0.0.1:3000/api/datasources
```

The sample uses the internal Compose hostname, the default database name and the isolated lab PostgreSQL transport. Adjust host and database if the stack uses different settings. For a TLS-enabled database, set `sslmode` to `verify-full`, configure the trusted CA in Grafana, and use a hostname matching the database certificate. In Grafana, open **Connections → Data sources → NetworkSec KPI PostgreSQL**, set the dedicated login password in the password field, and select **Save & test**. Keep the datasource UID `networksec-kpi-postgres` and restrict Grafana access to operators authorized to see the shared KPI data. Grafana authorization is separate from the NetworkSec API roles.

## Open from the dashboard API

Set `GRAFANA_PUBLIC_URL` to the address the UI user can reach, such as `http://localhost:3000` for a local lab or the deployed HTTPS URL with its Grafana subpath. `GET /api/v1/grafana/link` produces a Grafana URL with the requested UTC range and any supplied `device_name`, `device_id`, `severity`, `category`, or `incident_id` filters. A registry device UUID filters the KPI views directly. The Grafana link carries filter values only. Users authenticate to Grafana with their own credentials.

The dashboard uses the event catalog for replay-safe counts and ingestion metrics, the device view for current registry status, and the incident views for current state and latest resolutions in the selected window. See [KPI contract](kpi-contract.md) for time and attribution semantics.
