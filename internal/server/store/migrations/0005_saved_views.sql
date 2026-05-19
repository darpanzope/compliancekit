-- v1.5 Phase 2 — Saved filter views for the findings explorer.
--
-- Each saved view is a name + an opaque filter-string (URL query
-- fragment, e.g. "severity=critical,high&provider=aws&since_days=7")
-- + a pinned flag that shows the view under "Findings" in the sidebar.
--
-- Per-user views are scoped via owner_user_id; pinned-broadcast views
-- (owner_user_id NULL) appear in every user's nav (admin pattern for
-- shared team queries).

CREATE TABLE saved_views (
    id              TEXT PRIMARY KEY,
    owner_user_id   TEXT REFERENCES users(id) ON DELETE CASCADE,    -- NULL = team-wide
    created_at      TEXT NOT NULL,
    name            TEXT NOT NULL,
    query_string    TEXT NOT NULL DEFAULT '',     -- everything after the ? in /findings?…
    pinned          INTEGER NOT NULL DEFAULT 0     -- 0/1; pinned views render in the sidebar
);

CREATE INDEX idx_saved_views_owner ON saved_views (owner_user_id);
CREATE INDEX idx_saved_views_pinned ON saved_views (pinned);
