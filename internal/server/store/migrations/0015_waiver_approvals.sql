-- v1.9 phase 5 — Multi-approver waiver flows.
--
-- Waivers above a configurable severity threshold require N
-- approvers before becoming active. Existing single-approver
-- waivers from v0.18+ continue to work — required_approvers
-- defaults to 1, approvals_json defaults to [].
--
-- pending_since stamps when the waiver entered the multi-approval
-- queue so the /waivers UI can show "awaiting N more approvers"
-- + the v1.9 phase 6 expiry sweep can fire a stale-approval
-- nudge for waivers stuck pending for >7 days.

ALTER TABLE waivers ADD COLUMN required_approvers INTEGER NOT NULL DEFAULT 1;
ALTER TABLE waivers ADD COLUMN approvals_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE waivers ADD COLUMN pending_since TEXT;          -- NULL = active (legacy + auto-approved)
ALTER TABLE waivers ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'pending', 'rejected', 'revoked'));

CREATE INDEX idx_waivers_status ON waivers (status);
CREATE INDEX idx_waivers_pending_since ON waivers (pending_since);
