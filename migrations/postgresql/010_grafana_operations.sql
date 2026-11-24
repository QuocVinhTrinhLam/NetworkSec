-- Grant the Grafana reader SELECT on these views only.
CREATE VIEW grafana_incidents AS
SELECT alert.aggregate_id AS incident_id, alert.device_name, alert.rule_id,
       alert.status, alert.severity, alert.event_count, alert.first_seen, alert.last_seen,
       alert.status_changed_at, ospf.technical_recovered_at, ospf.superseded_at,
       adjacency.adjacency_key->>'scope' AS ospf_scope,
       adjacency.adjacency_key->>'link_id' AS ospf_link
FROM aggregated_alerts AS alert
LEFT JOIN ospf_incidents AS ospf USING (aggregate_id)
LEFT JOIN ospf_adjacencies AS adjacency USING (adjacency_id)
WHERE NOT EXISTS (
    SELECT 1 FROM interface_up_only_aggregates AS link WHERE link.aggregate_id = alert.aggregate_id
);

CREATE VIEW grafana_incident_history AS
SELECT history.aggregate_id AS incident_id, history.change_id, history.changed_at,
       history.previous_status, history.status, history.source
FROM alert_status_history AS history
JOIN grafana_incidents AS incident ON incident.incident_id = history.aggregate_id;

CREATE VIEW grafana_ospf_endpoints AS
WITH ranked AS (
    SELECT observed.*, max(observed_at) OVER endpoint AS last_observed_at,
           row_number() OVER (
               endpoint ORDER BY reliable DESC, observed_at DESC,
                                 (state = 'DOWN') DESC, observed.event_id DESC
           ) AS rank
    FROM ospf_link_observations AS observed
    JOIN event_catalog AS catalog USING (event_id)
    WINDOW endpoint AS (
        PARTITION BY observed.scope, link_id, observed.device_name, interface_name, area,
                     local_router_id, peer_router_id,
                     CASE WHEN link_id IS NULL THEN catalog.device_id END,
                     CASE WHEN link_id IS NULL THEN catalog.collector_ip END
    )
)
SELECT scope, link_id, host(area) AS area, device_name, interface_name,
       host(local_router_id) AS local_router_id, host(peer_router_id) AS peer_router_id,
       CASE WHEN reliable THEN state END AS neighbor_state, last_observed_at
FROM ranked WHERE rank = 1;
