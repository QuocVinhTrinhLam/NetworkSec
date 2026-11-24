CREATE TABLE interface_link_observations (
    event_id CHAR(64) PRIMARY KEY REFERENCES event_catalog (event_id),
    aggregate_id CHAR(64) NOT NULL REFERENCES aggregated_alerts (aggregate_id),
    endpoint_key TEXT CHECK (length(endpoint_key) = 64),
    observed_at TIMESTAMPTZ NOT NULL,
    is_down BOOLEAN NOT NULL
);
CREATE INDEX interface_link_observations_endpoint
    ON interface_link_observations (endpoint_key, observed_at, event_id);
CREATE INDEX interface_link_observations_alert ON interface_link_observations (aggregate_id);

CREATE TABLE interface_link_recoveries (
    aggregate_id CHAR(64) PRIMARY KEY REFERENCES aggregated_alerts (aggregate_id),
    event_id CHAR(64) NOT NULL REFERENCES interface_link_observations (event_id)
);
CREATE INDEX interface_link_recoveries_event ON interface_link_recoveries (event_id);

ALTER TABLE aggregated_alerts DROP CONSTRAINT aggregated_alerts_status_change_source_check;
ALTER TABLE aggregated_alerts ADD CHECK (
    status_change_source IN (
        'system', 'operator', 'ospf_recovery', 'ospf_reassessment',
        'interface_recovery', 'interface_reassessment', 'rule_recovery', 'rule_reassessment'
    )
);
ALTER TABLE alert_status_history DROP CONSTRAINT alert_status_history_source_check;
ALTER TABLE alert_status_history ADD CHECK (
    source IN (
        'baseline', 'system', 'operator', 'ospf_recovery', 'ospf_reassessment',
        'interface_recovery', 'interface_reassessment', 'rule_recovery', 'rule_reassessment'
    )
);

CREATE VIEW interface_up_only_aggregates AS
SELECT alert.aggregate_id
FROM aggregated_alerts AS alert
WHERE alert.rule_id = 'interface-link-state'
  AND alert.event_types = '["link_up"]'::jsonb
  AND EXISTS (
      SELECT 1 FROM interface_link_observations AS link
      WHERE link.aggregate_id = alert.aggregate_id
  );

CREATE OR REPLACE VIEW kpi_incident_events AS
SELECT DISTINCT refs.event_id, refs.aggregate_id AS incident_id
FROM (
    SELECT event_id, aggregate_id FROM alert_event_refs
    UNION ALL
    SELECT event_id, aggregate_id FROM ospf_incident_event_refs WHERE is_current
    UNION ALL
    SELECT event_id, aggregate_id FROM interface_link_recoveries
) AS refs
LEFT JOIN ospf_incidents AS ospf USING (aggregate_id)
WHERE ospf.superseded_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM interface_up_only_aggregates AS link
      WHERE link.aggregate_id = refs.aggregate_id
  );

CREATE OR REPLACE VIEW kpi_incident_facts AS
SELECT alert.aggregate_id AS incident_id, alert.first_seen, alert.last_seen,
       alert.status_changed_at, alert.severity, alert.status, alert.device_name, alert.event_types
FROM aggregated_alerts AS alert
LEFT JOIN ospf_incidents AS ospf USING (aggregate_id)
WHERE ospf.superseded_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM interface_up_only_aggregates AS link
      WHERE link.aggregate_id = alert.aggregate_id
  );
