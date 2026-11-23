CREATE TABLE ospf_notification_events (
    notification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    aggregate_id CHAR(64) NOT NULL REFERENCES ospf_incidents(aggregate_id),
    transition_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'down', 'recovered', 'recovery_retracted', 'acknowledged',
        'operator_resolved', 'operator_reopened', 'superseded'
    )),
    occurred_at TIMESTAMPTZ NOT NULL,
    actor VARCHAR(255),
    invalidated_at TIMESTAMPTZ,
    UNIQUE (aggregate_id, transition_key)
);

CREATE INDEX idx_ospf_notification_event_order
    ON ospf_notification_events (aggregate_id, notification_id);

CREATE TABLE ospf_telegram_deliveries (
    notification_id BIGINT NOT NULL REFERENCES ospf_notification_events(notification_id),
    chat_id BIGINT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('send', 'edit')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'delivered', 'skipped', 'uncertain')),
    claim_token UUID NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (notification_id, chat_id)
);

-- Bootstrap only open incidents. Existing Telegram message IDs are reused.
INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at)
SELECT alert.aggregate_id, 'opened', 'down', alert.first_seen
FROM ospf_incidents AS incident JOIN aggregated_alerts AS alert USING (aggregate_id)
WHERE incident.superseded_at IS NULL AND incident.technical_recovered_at IS NULL
  AND alert.status IN ('new', 'acknowledged')
ORDER BY alert.first_seen, alert.aggregate_id;

CREATE FUNCTION enqueue_ospf_incident_notification() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    adjacency_revision BIGINT;
    prior_recovery TIMESTAMPTZ;
    prior_superseded TIMESTAMPTZ;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at)
        SELECT aggregate_id, 'opened', 'down', first_seen
        FROM aggregated_alerts WHERE aggregate_id = NEW.aggregate_id
        ON CONFLICT (aggregate_id, transition_key) DO NOTHING;
    ELSE
        prior_recovery := OLD.technical_recovered_at;
        prior_superseded := OLD.superseded_at;
    END IF;

    SELECT revision INTO adjacency_revision FROM ospf_adjacencies
    WHERE adjacency_id = NEW.adjacency_id;

    IF NEW.superseded_at IS NOT NULL OR
       (prior_recovery IS NOT NULL AND NEW.technical_recovered_at IS NULL) THEN
        UPDATE ospf_notification_events SET invalidated_at = now()
        WHERE aggregate_id = NEW.aggregate_id AND kind = 'recovered' AND invalidated_at IS NULL;
    END IF;

    IF NEW.superseded_at IS NOT NULL THEN
        IF prior_superseded IS NULL THEN
            INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at)
            VALUES (
                NEW.aggregate_id, 'superseded:' || adjacency_revision, 'superseded', NEW.superseded_at
            )
            ON CONFLICT (aggregate_id, transition_key) DO NOTHING;
        END IF;
    ELSIF prior_recovery IS NULL AND NEW.technical_recovered_at IS NOT NULL THEN
        INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at)
        VALUES (
            NEW.aggregate_id, 'recovered:' || adjacency_revision, 'recovered',
            NEW.technical_recovered_at
        )
        ON CONFLICT (aggregate_id, transition_key) DO NOTHING;
    ELSIF prior_recovery IS NOT NULL AND NEW.technical_recovered_at IS NULL THEN
        INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at)
        VALUES (
            NEW.aggregate_id, 'retracted:' || adjacency_revision, 'recovery_retracted', now()
        )
        ON CONFLICT (aggregate_id, transition_key) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ospf_incident_notification
    AFTER INSERT OR UPDATE OF technical_recovered_at, superseded_at ON ospf_incidents
    FOR EACH ROW EXECUTE FUNCTION enqueue_ospf_incident_notification();

CREATE FUNCTION enqueue_ospf_operator_notification() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO ospf_notification_events (aggregate_id, transition_key, kind, occurred_at, actor)
    SELECT aggregate_id, 'operator:' || NEW.change_id, CASE NEW.status
        WHEN 'new' THEN 'operator_reopened'
        WHEN 'acknowledged' THEN 'acknowledged'
        WHEN 'resolved' THEN 'operator_resolved'
    END, NEW.changed_at, NEW.actor
    FROM ospf_incidents
    WHERE aggregate_id = NEW.aggregate_id AND superseded_at IS NULL
    ON CONFLICT (aggregate_id, transition_key) DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ospf_operator_notification
    AFTER INSERT ON alert_status_history
    FOR EACH ROW WHEN (NEW.source = 'operator')
    EXECUTE FUNCTION enqueue_ospf_operator_notification();
