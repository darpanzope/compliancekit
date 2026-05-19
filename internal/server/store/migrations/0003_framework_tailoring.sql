-- v1.4 Phase 5 — Framework tailoring table.
--
-- Per-(framework, control) include/exclude with a required
-- justification text. Auditors get the rationale at the same row
-- they get the scope decision. The v0.12 tailoring CLI wrote this
-- shape into evidence/tailoring.json; the v1.4 UI keeps the source
-- of truth in this table and the v1.4 Phase 7 generator emits the
-- equivalent YAML into compliancekit.yaml.

CREATE TABLE framework_tailoring (
    framework_id          TEXT NOT NULL,
    control_id            TEXT NOT NULL,
    included              INTEGER NOT NULL DEFAULT 1,    -- 0/1; default scope is "included"
    justification         TEXT NOT NULL DEFAULT '',     -- required when included=0; stored "" otherwise
    updated_by_user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (framework_id, control_id)
);

CREATE INDEX idx_framework_tailoring_framework ON framework_tailoring (framework_id);
