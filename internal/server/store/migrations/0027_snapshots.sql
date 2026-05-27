-- v1.17 phase 6 — point-in-time warehouse snapshots.
--
-- A snapshot captures the upper-bound id for every canonical
-- warehouse table at the moment of creation. Subsequent reads
-- scoped to the snapshot include only rows with id <= the
-- recorded cursor, so the same query returns identical rows
-- even after live scans modify the tables.
--
-- content_hash is the sha256 of "<findings_cursor>|<resources_cursor>
-- |<scans_cursor>|<audit_cursor>" so any drift in the captured
-- cursors produces a distinct hash. Operators compose snapshots
-- with warehouse loaders ("export the q1-2026 snapshot to BigQuery").

CREATE TABLE snapshots (
    name              TEXT PRIMARY KEY,
    content_hash      TEXT NOT NULL,
    findings_cursor   TEXT NOT NULL DEFAULT '',
    resources_cursor  TEXT NOT NULL DEFAULT '',
    scans_cursor      TEXT NOT NULL DEFAULT '',
    audit_cursor      TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL,
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_snapshots_created_at ON snapshots (created_at);
