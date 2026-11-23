ALTER TABLE alert_event_refs
    ADD COLUMN source_ip INET,
    ADD COLUMN event_type VARCHAR(64);

CREATE INDEX idx_alert_event_refs_source_ip
    ON alert_event_refs (source_ip, aggregate_id) WHERE source_ip IS NOT NULL;
