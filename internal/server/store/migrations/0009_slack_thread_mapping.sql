-- v1.8 phase 5 — Slack reply-in-thread mapping.
--
-- The v0.17 outbound Slack notifier posts one Block Kit message per
-- finding. To turn replies in that thread into compliancekit
-- comments, we need a stable mapping from
-- (Slack channel, Slack thread_ts) → finding fingerprint.
--
-- The outbound notifier (internal/notify/slack/) writes to this
-- table at post time when daemon mode is configured; the inbound
-- /webhooks/slack/events handler reads it when Slack delivers a
-- message event referencing one of our thread_ts values.
--
-- The composite PK enforces one finding per Slack thread: any
-- re-post of the same finding into the same channel writes a new
-- row (different thread_ts), so the mapping is many-channels-to-one-
-- fingerprint, never the inverse.
--
-- created_at is the post time recorded by the outbound side;
-- inbound handlers don't update it (the thread itself is durable).

CREATE TABLE slack_thread_mapping (
    channel        TEXT NOT NULL,
    thread_ts      TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (channel, thread_ts)
);
CREATE INDEX idx_slack_mapping_fingerprint ON slack_thread_mapping (fingerprint);
