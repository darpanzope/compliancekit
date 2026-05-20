-- v1.8 phase 7 — Jira / Linear two-way sync.
--
-- The v0.15 remediation pipeline already ships tickets.Jira +
-- tickets.Linear for creating issues. v1.8 phase 7 layers two-way
-- sync: a finding may also be linked to an existing issue created
-- outside the remediation flow; webhook deliveries from
-- Jira/Linear flip the finding state when the linked issue closes.
--
-- The mapping is N:N — one finding can be linked to multiple
-- external issues (you might track the same control in both Jira
-- and Linear), and one external issue can cover multiple findings
-- (a single Jira epic covering a class of misconfigurations).
--
-- system: "jira" | "linear" (mirrors notify sink names)
-- external_id: Jira "PROJ-123", Linear "ABC-45"
-- external_url: the canonical URL (Jira REST host can change; the
--               URL captures the operator's resolved web URL)

CREATE TABLE external_issue_mapping (
    id              TEXT PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    system          TEXT NOT NULL CHECK (system IN ('jira', 'linear')),
    external_id     TEXT NOT NULL,                       -- "PROJ-123" / "ABC-45"
    external_url    TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    closed_at       TEXT,
    UNIQUE (system, external_id, fingerprint)
);
CREATE INDEX idx_ext_issue_fingerprint ON external_issue_mapping (fingerprint);
CREATE INDEX idx_ext_issue_system_extid ON external_issue_mapping (system, external_id);
