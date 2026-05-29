-- v1.19 phase 8 — finding triage state + inline note.
--
-- findings.status is the scan RESULT (pass/fail/skip/error) and never
-- changes after a scan. Triage is a separate, operator-owned lifecycle:
-- open → acknowledged → resolved (or false-positive). The bulk-actions
-- bar + the inline-edit note both write here + append a v1.12 audit_log
-- entry. note is a short free-text triage annotation editable in place
-- on the finding detail panel.
ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN note TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_findings_triage_status ON findings (triage_status);
