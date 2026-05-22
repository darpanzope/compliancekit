-- v1.12 phase 8 — backups catalog.
--
-- One row per backup the daemon has taken. The actual dump lives on
-- the host filesystem under the path column. Restore is a daemon-
-- restart operation (stop the worker pool, swap the SQLite file or
-- `pg_restore` the dump, restart) — the catalog is just the
-- index so the operator can pick which one.

CREATE TABLE backups (
    id           TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('sqlite', 'postgres')),
    path         TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'ok'
                     CHECK (status IN ('ok', 'failed', 'in_progress')),
    note         TEXT NOT NULL DEFAULT '',
    triggered_by TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_backups_created_at ON backups (created_at);
CREATE INDEX idx_backups_status ON backups (status);
