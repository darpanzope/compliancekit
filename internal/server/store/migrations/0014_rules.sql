-- v1.9 phase 0 — Rules engine schema.
--
-- Rules are operator-authored if-this-then-that programs the daemon
-- evaluates against findings + events. The shape stays JSON-on-disk
-- so the engine can evolve condition/action types without a schema
-- migration per new operator.
--
-- Each row carries the condition tree, the action list, a priority
-- (lowest first), and an enabled flag for kill-switch + drafting.
-- The rule_runs table is the append-only audit trail used by the
-- v1.9 phase 8 simulator + the v1.5.1 audit_log integration.

CREATE TABLE rules (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    enabled             INTEGER NOT NULL DEFAULT 1,         -- 0/1
    priority            INTEGER NOT NULL DEFAULT 100,       -- lower runs first
    trigger             TEXT NOT NULL DEFAULT 'finding.created'
                            CHECK (trigger IN (
                                'finding.created', 'finding.resolved',
                                'scan.completed', 'waiver.expired', 'cron')),
    cron_expr           TEXT,                                -- non-NULL when trigger='cron'
    timezone            TEXT NOT NULL DEFAULT 'UTC',
    condition_json      TEXT NOT NULL DEFAULT '{}',         -- condition tree
    action_json         TEXT NOT NULL DEFAULT '[]',         -- ordered action list
    created_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX idx_rules_trigger_enabled ON rules (trigger, enabled);
CREATE INDEX idx_rules_priority ON rules (priority);

-- ─── rule_runs ─────────────────────────────────────────────────────────
-- One row per rule invocation. Records the matching outcome + the
-- action results so the simulator can replay history + the operator
-- can debug a rule that didn't fire.

CREATE TABLE rule_runs (
    id              TEXT PRIMARY KEY,
    rule_id         TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    triggered_at    TEXT NOT NULL,
    trigger_event   TEXT NOT NULL,                          -- 'finding.created' etc
    fingerprint     TEXT,                                    -- finding fingerprint when applicable
    matched         INTEGER NOT NULL,                        -- 0/1 — condition tree result
    actions_json    TEXT NOT NULL DEFAULT '[]',              -- dispatched-action outcomes
    simulated       INTEGER NOT NULL DEFAULT 0,              -- 1 = recorded by phase 8 simulator
    duration_ms     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_rule_runs_rule_id ON rule_runs (rule_id, triggered_at);
CREATE INDEX idx_rule_runs_fingerprint ON rule_runs (fingerprint);
CREATE INDEX idx_rule_runs_simulated ON rule_runs (simulated);
