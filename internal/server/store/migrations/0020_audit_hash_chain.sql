-- v1.12 phase 10 — tamper-evident audit log via SHA-256 hash chain.
--
-- Every row's row_hash = SHA-256(prev_row_hash || canonical_json(row)).
-- The first row's prev_hash is the all-zero SHA-256.
--
-- compliancekit serve audit verify walks the log + recomputes each
-- hash. A mismatch proves the row (or one before it) was tampered.
--
-- Existing rows (pre-v1.12) are not retro-actively chained — the
-- columns default NULL on backfill + the verify command treats
-- NULL-hashed rows as "unchained legacy" and skips them. Operators
-- who care about full-history integrity start a fresh log after
-- upgrade (export old → archive → truncate → next row is chain
-- genesis).

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN row_hash  TEXT;
CREATE INDEX idx_audit_log_row_hash ON audit_log (row_hash);
