-- v1.11 phase 2 — Covering indexes for cursor pagination + hot
-- filter combos.
--
-- v1.11 phase 0 introduced cursor-based pagination keyed on
-- (sort_key, id). The pre-existing single-column indexes
-- (idx_findings_created_at, idx_scans_created_at,
-- idx_resources_last_seen) cover the legacy OFFSET path but
-- force a second per-row lookup for the cursor's tuple compare.
-- These composite indexes let the planner serve the cursor
-- query from the index alone — linear scaling to 100k+ rows.
--
-- The findings explorer (v1.5) hot paths cross-filter by
-- (severity, status, provider) + cursor; the partial composite
-- indexes below cover the three most common chips.
--
-- Documentation: internal/server/store/sql_perf.md.

-- ─── Cursor base indexes ────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_findings_created_id ON findings (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created_id ON scans (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_resources_lastseen_id ON resources (last_seen_at DESC, id DESC);

-- ─── Filter + cursor compositions ───────────────────────────────────────
-- The most common explorer cross-filter combos. The planner picks
-- one of these when both a filter chip is set AND a cursor is in
-- play. Without the composite, the planner falls back to a scan
-- on the filter index + post-filter — fine at 1k rows, painful
-- at 100k.
CREATE INDEX IF NOT EXISTS idx_findings_severity_created ON findings (severity, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status_created ON findings (status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_provider_created ON findings (provider, created_at DESC, id DESC);

-- ─── Audit log search ───────────────────────────────────────────────────
-- v1.12 audit log search lands soon; pre-create the index it needs
-- here so v1.11 doesn't have to migrate twice.
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_created ON audit_log (actor_user_id, created_at DESC);

-- ─── Inbox unread + event_type ──────────────────────────────────────────
-- Inbox 2.0 added an event_type column (migration 0013) but no index
-- for the filter-by-event-type-then-newest-first query the UI sends.
CREATE INDEX IF NOT EXISTS idx_inbox_user_event_type ON inbox (user_id, event_type, created_at DESC);
