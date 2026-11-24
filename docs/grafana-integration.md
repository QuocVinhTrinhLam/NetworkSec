# Grafana integration

Grafana serves four provisioned dashboards in **Network Operations**.

| Dashboard | Datasource | Use |
| --- | --- | --- |
| Network Event Operations | Loki | Normalized event volume and log investigation |
| OSPF Observability | Loki | Down, Full and intermediate observations from both routers |
| Network Event KPIs | PostgreSQL | Distinct event counts, device status and incident KPIs |
| Incident Operations | PostgreSQL | Incident queue, status history, confirmed OSPF recovery and endpoint evidence |

In **Incident Operations**, select an incident ID to show its history and mapped OSPF endpoint evidence. An explicit ID can open an older or superseded incident. The default queue excludes superseded incidents and shows overlapping incidents with their current recorded status. The OSPF table reports the last reliable state per endpoint. Rows without a configured link represent unmapped observations. The full inventory and topology, incident evidence and operator notes are available through the operational API. Use that API to acknowledge or resolve incidents.

## Configure PostgreSQL access

After the backend applies the migrations, connect to the configured database as its owner. The example assumes database `networksec`, schema `public`, and a new dedicated login.

```sql
CREATE ROLE networksec_kpi LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
GRANT CONNECT ON DATABASE networksec TO networksec_kpi;
GRANT USAGE ON SCHEMA public TO networksec_kpi;
GRANT SELECT ON public.kpi_event_facts, public.kpi_device_facts,
    public.kpi_incident_facts, public.kpi_incident_events,
    public.grafana_incidents, public.grafana_incident_history,
    public.grafana_ospf_endpoints TO networksec_kpi;
ALTER ROLE networksec_kpi SET default_transaction_read_only = on;
ALTER ROLE networksec_kpi SET statement_timeout = '10s';
```

Set the login password with the PostgreSQL interactive `\password networksec_kpi` command. If the role already exists, grant it `SELECT` on the three `grafana_*` views after migration `010`. The views expose event and incident metadata, device names, and observed OSPF router IDs. The grants exclude PostgreSQL base tables, operator notes, raw logs, credentials and audit records.

Create an editable datasource with the supplied JSON sample. Use a local Grafana administrator login. `curl` prompts for the Grafana password.

```sh
curl --fail-with-body --user admin \
  --header 'Content-Type: application/json' \
  --data-binary @infra/grafana/kpi-postgres.datasource.example.json \
  http://127.0.0.1:3000/api/datasources
```

The sample uses the internal Compose hostname, the default database name and the isolated lab PostgreSQL transport. Adjust host and database if the stack uses different settings. For a TLS-enabled database, set `sslmode` to `verify-full`, configure the trusted CA in Grafana, and use a hostname matching the database certificate. In Grafana, open **Connections → Data sources → NetworkSec KPI PostgreSQL**, set the dedicated login password in the password field, and select **Save & test**. Keep the datasource UID `networksec-kpi-postgres` and restrict Grafana access to operators authorized to see the shared KPI data. Grafana authorization is separate from the NetworkSec API roles.

## Open from the API or Telegram

Set `GRAFANA_PUBLIC_URL` to the address the UI user can reach, such as `http://localhost:3000` for a local lab or the deployed HTTPS URL with its Grafana subpath. `GET /api/v1/grafana/link` produces a Grafana URL with the requested UTC range and any supplied `device_name`, `device_id`, `severity`, `category`, or `incident_id` filters. A registry device UUID filters the KPI views directly. The Grafana link carries filter values only. Users authenticate to Grafana with their own credentials.

PostgreSQL-backed Telegram notifications link directly to **Incident Operations** using the incident ID. Set a Grafana URL reachable by recipients. The bot omits the button when its URL is missing, local-only or invalid. SQLite-only notifications continue to support Telegram callbacks.

The dashboard uses the event catalog for replay-safe counts and ingestion metrics, the device view for current registry status, and the incident views for current state and latest resolutions in the selected window. See [KPI contract](kpi-contract.md) for time and attribution semantics.
