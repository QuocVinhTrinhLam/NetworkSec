ALTER TABLE aggregated_alerts
    ADD COLUMN status_change_source TEXT NOT NULL DEFAULT 'system'
    CHECK (status_change_source IN ('system', 'operator', 'ospf_recovery', 'ospf_reassessment'));

CREATE TABLE alert_status_history (
    change_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    aggregate_id CHAR(64) NOT NULL REFERENCES aggregated_alerts(aggregate_id),
    previous_status VARCHAR(16) CHECK (previous_status IN ('new', 'acknowledged', 'resolved')),
    status VARCHAR(16) NOT NULL CHECK (status IN ('new', 'acknowledged', 'resolved')),
    source TEXT NOT NULL
        CHECK (source IN ('baseline', 'system', 'operator', 'ospf_recovery', 'ospf_reassessment')),
    actor VARCHAR(255),
    note VARCHAR(1000),
    changed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_alert_status_history_aggregate
    ON alert_status_history (aggregate_id, change_id);

-- Existing rows supply a baseline only. Their earlier transitions are unknown.
INSERT INTO alert_status_history (aggregate_id, status, source, actor, note, changed_at)
SELECT aggregate_id, status, 'baseline', status_changed_by, note, status_changed_at
FROM aggregated_alerts;

CREATE FUNCTION record_alert_status_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    prior_status VARCHAR(16);
BEGIN
    IF TG_OP = 'UPDATE' THEN
        prior_status := OLD.status;
    END IF;
    IF prior_status IS DISTINCT FROM NEW.status THEN
        INSERT INTO alert_status_history (
            aggregate_id, previous_status, status, source, actor, note, changed_at
        ) VALUES (
            NEW.aggregate_id, prior_status, NEW.status, NEW.status_change_source,
            NEW.status_changed_by, NEW.note, NEW.status_changed_at
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER alert_status_change
    AFTER INSERT OR UPDATE OF status ON aggregated_alerts
    FOR EACH ROW EXECUTE FUNCTION record_alert_status_change();

CREATE TABLE ospf_adjacencies (
    adjacency_id CHAR(64) PRIMARY KEY,
    adjacency_key JSONB NOT NULL CHECK (jsonb_typeof(adjacency_key) = 'object'),
    revision BIGINT NOT NULL CHECK (revision >= 0)
);

CREATE TABLE ospf_incidents (
    aggregate_id CHAR(64) PRIMARY KEY REFERENCES aggregated_alerts(aggregate_id),
    adjacency_id CHAR(64) NOT NULL REFERENCES ospf_adjacencies(adjacency_id),
    reporters JSONB NOT NULL CHECK (jsonb_typeof(reporters) = 'array'),
    technical_recovered_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    UNIQUE (adjacency_id, aggregate_id)
);

CREATE TABLE ospf_incident_event_refs (
    adjacency_id CHAR(64) NOT NULL,
    aggregate_id CHAR(64) NOT NULL,
    event_id CHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    reporter_router_id INET NOT NULL
        CHECK (family(reporter_router_id) = 4 AND masklen(reporter_router_id) = 32),
    event_type VARCHAR(64) NOT NULL
        CHECK (event_type IN ('routing_neighbor_down', 'routing_neighbor_up')),
    is_current BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (aggregate_id, event_id),
    FOREIGN KEY (adjacency_id, aggregate_id) REFERENCES ospf_incidents(adjacency_id, aggregate_id)
);

CREATE UNIQUE INDEX idx_ospf_current_event_assignment
    ON ospf_incident_event_refs (adjacency_id, event_id) WHERE is_current;
