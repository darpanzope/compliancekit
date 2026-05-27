-- v1.17 phase 7 — scheduled warehouse sync.
--
-- One row per (target, dataset). cron is robfig/cron/v3 syntax.
-- last_status / last_error / last_run_at let /audit + /scans show
-- the most recent sync outcome alongside the v1.6 activity timeline.
-- next_run_at is computed forward each tick by the WarehouseScheduler
-- loop in internal/server/worker/.

CREATE TABLE warehouse_schedules (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    target        TEXT NOT NULL,           -- bigquery / snowflake / redshift
    cron          TEXT NOT NULL,           -- robfig/cron/v3 — daily at 03:00 UTC = "0 0 3 * * *"
    config_json   TEXT NOT NULL DEFAULT '{}', -- target-specific knobs (project, dataset, account, …)
    snapshot_name TEXT,                    -- optional — pin loads to a snapshot
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_run_at   TEXT,
    last_status   TEXT,                    -- ok / failed / running
    last_error    TEXT,
    next_run_at   TEXT
);
CREATE INDEX idx_warehouse_schedules_next ON warehouse_schedules (next_run_at, enabled);
