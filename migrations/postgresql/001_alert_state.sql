CREATE TABLE aggregated_alerts (
    aggregate_id CHAR(64) PRIMARY KEY,
    schema_version VARCHAR(16) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    event_family VARCHAR(64) NOT NULL,
    group_key JSONB NOT NULL,
    device_name VARCHAR(255),
    interface_name VARCHAR(255),
    event_types JSONB NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count >= 1),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(16) NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'acknowledged', 'resolved')),
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    status_changed_by VARCHAR(255),
    status_changed_at TIMESTAMPTZ NOT NULL,
    note VARCHAR(1000),
    notification_cooldown_seconds INTEGER NOT NULL CHECK (notification_cooldown_seconds >= 1),
    last_notification_at TIMESTAMPTZ,
    notification_count INTEGER NOT NULL DEFAULT 0 CHECK (notification_count >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (window_end > window_start),
    CHECK (last_seen >= first_seen),
    CHECK (jsonb_typeof(group_key) = 'object'),
    CHECK (jsonb_typeof(event_types) = 'array')
);

CREATE INDEX idx_aggregated_alerts_last_seen
    ON aggregated_alerts (last_seen DESC, aggregate_id DESC);
CREATE INDEX idx_aggregated_alerts_severity_time
    ON aggregated_alerts (severity, last_seen DESC);
CREATE INDEX idx_aggregated_alerts_status_time
    ON aggregated_alerts (status, last_seen DESC);
CREATE INDEX idx_aggregated_alerts_device_time
    ON aggregated_alerts (device_name, last_seen DESC);
CREATE INDEX idx_aggregated_alerts_event_types
    ON aggregated_alerts USING GIN (event_types);

CREATE TABLE alert_event_refs (
    event_id CHAR(64) PRIMARY KEY,
    aggregate_id CHAR(64) NOT NULL REFERENCES aggregated_alerts(aggregate_id) ON DELETE CASCADE,
    event_timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_event_refs_aggregate
    ON alert_event_refs (aggregate_id, event_timestamp, event_id);
