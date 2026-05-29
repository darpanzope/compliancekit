-- v1.19 phase 2 — in-app feedback queue.
--
-- One row per submission from the corner feedback widget. kind is
-- bug / feature / love; status is the admin triage state. user_email is
-- denormalised so the admin queue reads cleanly even after a user is
-- deleted (the FK then nulls user_id). page_url records where the
-- operator was when they hit the widget.
CREATE TABLE feedback (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    user_email  TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    page_url    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'new',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_feedback_status ON feedback (status, created_at);
