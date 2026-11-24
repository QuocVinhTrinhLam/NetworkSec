-- Grant a dedicated Grafana role SELECT on these views only.
CREATE VIEW kpi_incident_events AS
SELECT DISTINCT refs.event_id, refs.aggregate_id AS incident_id
FROM (
    SELECT event_id, aggregate_id FROM alert_event_refs
    UNION ALL
    SELECT event_id, aggregate_id FROM ospf_incident_event_refs WHERE is_current
) AS refs
LEFT JOIN ospf_incidents AS ospf USING (aggregate_id)
WHERE ospf.superseded_at IS NULL;

CREATE VIEW kpi_incident_facts AS
SELECT alert.aggregate_id AS incident_id, alert.first_seen, alert.last_seen,
       alert.status_changed_at, alert.severity, alert.status, alert.device_name, alert.event_types
FROM aggregated_alerts AS alert
LEFT JOIN ospf_incidents AS ospf USING (aggregate_id)
WHERE ospf.superseded_at IS NULL;

CREATE VIEW kpi_device_facts AS
SELECT device_id, name, CASE
    WHEN NOT enabled THEN 'disabled'
    WHEN last_seen IS NULL OR expected_interval_seconds IS NULL THEN 'unknown'
    WHEN last_seen >= now() - make_interval(secs => expected_interval_seconds) THEN 'active'
    ELSE 'stale'
END AS status
FROM devices;
