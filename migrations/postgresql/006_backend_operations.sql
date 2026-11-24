CREATE TABLE devices (
    device_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL CHECK (length(btrim(name)) > 0),
    hostname VARCHAR(253),
    management_ip INET UNIQUE,
    device_type TEXT NOT NULL CHECK (device_type IN ('router','switch','firewall','server','segment','other')),
    vendor TEXT CHECK (vendor IN ('cisco','mikrotik','pfsense')),
    model VARCHAR(120),
    location VARCHAR(120),
    description VARCHAR(1000),
    enabled BOOLEAN NOT NULL DEFAULT true,
    expected_interval_seconds INTEGER CHECK (expected_interval_seconds BETWEEN 60 AND 604800),
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX devices_name_unique ON devices (lower(name));
CREATE UNIQUE INDEX devices_hostname_unique ON devices (lower(hostname));

CREATE TABLE device_syslog_sources (
    address INET PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices (device_id)
);
CREATE INDEX device_syslog_sources_device ON device_syslog_sources (device_id);

CREATE TABLE event_catalog (
    event_id CHAR(64) PRIMARY KEY,
    event_timestamp TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    device_id UUID REFERENCES devices (device_id),
    device_name VARCHAR(255),
    collector_ip INET,
    source_ip INET,
    vendor TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    event_type TEXT NOT NULL,
    category TEXT NOT NULL,
    message VARCHAR(4096) NOT NULL,
    parser_name VARCHAR(64) NOT NULL,
    syslog_priority SMALLINT CHECK (syslog_priority BETWEEN 0 AND 191),
    raw_prefix BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX event_catalog_time ON event_catalog (event_timestamp DESC, event_id DESC);
CREATE INDEX event_catalog_device_time ON event_catalog (device_id, event_timestamp DESC, event_id DESC);
CREATE INDEX event_catalog_severity_time ON event_catalog (severity, event_timestamp DESC);
CREATE INDEX event_catalog_ingested ON event_catalog (ingested_at DESC);

CREATE TABLE ospf_link_observations (
    event_id CHAR(64) PRIMARY KEY REFERENCES event_catalog (event_id),
    adjacency_id CHAR(64),
    link_id VARCHAR(255),
    scope VARCHAR(255) NOT NULL,
    area INET,
    device_name VARCHAR(255),
    interface_name VARCHAR(255),
    local_router_id INET,
    peer_router_id INET NOT NULL,
    state TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    reliable BOOLEAN NOT NULL
);
CREATE INDEX ospf_link_observations_recent
    ON ospf_link_observations (adjacency_id, local_router_id, observed_at DESC, event_id DESC);

CREATE TABLE api_users (
    username VARCHAR(100) PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE api_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    bootstrap_version CHAR(64),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX api_sessions_expiry ON api_sessions (expires_at);
CREATE INDEX api_sessions_username ON api_sessions (username);

CREATE TABLE application_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    actor_id VARCHAR(100),
    action VARCHAR(80) NOT NULL,
    resource_type VARCHAR(40) NOT NULL,
    resource_id VARCHAR(255),
    request_id UUID,
    outcome TEXT NOT NULL CHECK (outcome IN ('success','failure')),
    metadata JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX application_audit_timestamp ON application_audit (timestamp DESC, audit_id DESC);
CREATE INDEX application_audit_action ON application_audit (action, audit_id DESC);

CREATE FUNCTION audit_operator_incident_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status AND NEW.status_change_source = 'operator' THEN
        INSERT INTO application_audit (actor_id, action, resource_type, resource_id, request_id,
                                       outcome, metadata)
        VALUES (left(NEW.status_changed_by, 100), 'incident.status', 'incident', NEW.aggregate_id,
                nullif(current_setting('networksec.request_id', true), '')::uuid, 'success',
                jsonb_build_object('previous_status', OLD.status, 'status', NEW.status));
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_operator_incident_change AFTER UPDATE OF status ON aggregated_alerts
    FOR EACH ROW EXECUTE FUNCTION audit_operator_incident_change();

CREATE INDEX ospf_evidence_event ON ospf_incident_event_refs (event_id) WHERE is_current;

-- Deliberately excludes messages, addresses and security administration data.
CREATE VIEW kpi_event_facts AS
SELECT event_id, event_timestamp, ingested_at, device_id, device_name, severity, category
FROM event_catalog;
