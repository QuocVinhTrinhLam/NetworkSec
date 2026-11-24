CREATE TABLE managed_rules (
    id VARCHAR(128) PRIMARY KEY,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    enabled BOOLEAN NOT NULL DEFAULT false,
    definition JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rule_windows (
    aggregate_id CHAR(64) PRIMARY KEY,
    recovery_at TIMESTAMPTZ,
    managed_recovery_at TIMESTAMPTZ
);

CREATE TABLE rule_window_events (
    event_id CHAR(64) PRIMARY KEY REFERENCES event_catalog (event_id),
    aggregate_id CHAR(64) NOT NULL REFERENCES rule_windows (aggregate_id),
    dedup_key CHAR(64) NOT NULL,
    recovered BOOLEAN NOT NULL
);
CREATE INDEX rule_window_events_aggregate ON rule_window_events (aggregate_id);

INSERT INTO managed_rules (id, enabled, definition) VALUES
    ('repeated-login-failures', true,
     '{"name":"Repeated authentication failures","description":"Repeated verified login failures","event_types":["login_failure"],"group_by":["device_name"],"threshold":5,"window_seconds":300,"severity":"high","category":"authentication"}'),
    ('repeated-firewall-denies', true,
     '{"name":"Repeated firewall denies","description":"Repeated deny observations from a single source","event_types":["acl_deny"],"group_by":["device_name","source_ip"],"threshold":20,"window_seconds":300,"severity":"medium","category":"firewall"}'),
    ('configuration-change', true,
     '{"name":"Configuration change","description":"Verified device configuration changes","event_types":["configuration_change"],"group_by":["device_name"],"threshold":1,"window_seconds":60,"severity":"medium","category":"configuration"}'),
    ('repeated-port-flap', false,
     '{"name":"Repeated port flaps","description":"Pending a verified port_flap parser or data source","event_types":["port_flap"],"group_by":["device_name","interface_name"],"threshold":3,"window_seconds":300,"severity":"medium","category":"interface"}');
