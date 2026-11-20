ALTER TABLE aggregated_alerts
    ADD COLUMN last_notification_event_count BIGINT NOT NULL DEFAULT 0
    CHECK (last_notification_event_count >= 0);

CREATE TABLE telegram_message_state (
    aggregate_id CHAR(64) NOT NULL REFERENCES aggregated_alerts(aggregate_id) ON DELETE CASCADE,
    chat_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (aggregate_id, chat_id)
);
