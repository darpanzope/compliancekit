-- v1.14 phase 6 — scheduled dashboard reports.
--
-- One row per (dashboard, schedule, recipient-set). The daemon's
-- ScheduledReports loop polls this table every minute, matches cron
-- expressions against the wall clock, and emits a markdown summary
-- + PDF attachment via the v0.17 email sink.
--
-- last_run_at + last_status surface in the /settings/scheduled-
-- reports admin UI so the operator can see whether the latest
-- delivery succeeded without grepping the daemon log.

CREATE TABLE scheduled_reports (
    id              TEXT PRIMARY KEY,
    dashboard_id    TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    cron_expr       TEXT NOT NULL,                -- robfig/cron v3 syntax
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    recipients      TEXT NOT NULL,                -- comma-separated email list
    subject         TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,   -- 0/1
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_run_at     TEXT,
    last_status     TEXT NOT NULL DEFAULT '',     -- '', 'ok', 'failed:<reason>'
    next_run_at     TEXT                          -- materialized when enabled, refreshed on every tick
);
CREATE INDEX idx_scheduled_reports_enabled_next ON scheduled_reports (enabled, next_run_at);
CREATE INDEX idx_scheduled_reports_dashboard ON scheduled_reports (dashboard_id);
