-- v1.11 phase 3 — Materialised per-scan resource + severity counts.
--
-- The existing scans.total_findings + actionable_findings cover
-- the top-line dashboard cards. v1.11 phase 3 extends with two
-- more rollups that the dashboard pulls every page load — and
-- recomputing them per-load is the actual cost driver for the
-- /scans + home dashboards at 100k findings:
--
--   resource_count: COUNT(DISTINCT resource_id) WHERE scan_id = ?
--     — the v1.5 inventory header reads this; without the rollup
--     it triggers a 3-second sort on every page load.
--
--   severity_breakdown_json: {critical: N, high: N, medium: N,
--     low: N, info: N}. The v1.2 HTML report donut + the v1.1
--     CLI severity histogram both want this; computing it at
--     render time means a 5-row GROUP BY scan per render.
--
-- Computed in RealRunner.persistFindings at scan-completion time
-- (a single pass over the same finding slice it already iterates).
-- Backfill for v1.10-era scans is a no-op — the columns default
-- NULL + 0, the reader paths treat absence as "compute on demand"
-- (the current v1.10 behavior) so the migration is zero-cost.

ALTER TABLE scans ADD COLUMN resource_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN severity_breakdown_json TEXT NOT NULL DEFAULT '{}';
