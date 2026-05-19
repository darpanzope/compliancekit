-- v1.4 Phase 11 — in-UI inbox.
--
-- Distinct from v0.17 outbound notifications (Slack/Teams/etc.). The
-- inbox is per-user in-app alerts the operator sees in the daemon
-- chrome: new high/critical finding, scan completed, waiver expiring
-- soon, schedule fired with an error.
--
-- read_at NULL = unread. The nav bar's unread badge reads
-- COUNT(*) WHERE user_id = ? AND read_at IS NULL.

CREATE TABLE inbox (
    id              TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(id) ON DELETE CASCADE,    -- NULL = broadcast to every user
    created_at      TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'success', 'warning', 'critical')),
    title           TEXT NOT NULL,
    body            TEXT NOT NULL DEFAULT '',
    href            TEXT,                                            -- click-through link
    read_at         TEXT                                             -- NULL = unread
);

CREATE INDEX idx_inbox_user_unread ON inbox (user_id, read_at);
CREATE INDEX idx_inbox_created_at ON inbox (created_at);
