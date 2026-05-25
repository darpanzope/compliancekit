-- v1.13 phase 6 — notification template editor storage.
--
-- One row per (kind, name) — operators can override the daemon's
-- default templates for each notification sink (slack / teams / email
-- / webhook / jira / linear / pagerduty) and save multiple named
-- variants (e.g. "critical-only", "weekly-digest").
--
-- The body is a Go text/template string evaluated against the finding
-- payload at dispatch time. The renderer is the same one the
-- /settings/notify-templates preview uses, so what the operator sees
-- in the editor matches what the sink receives.

CREATE TABLE notify_templates (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL
                     CHECK (kind IN ('slack', 'teams', 'email', 'webhook',
                                     'jira', 'linear', 'pagerduty', 'discord', 'github')),
    name         TEXT NOT NULL DEFAULT 'default',
    body         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE (kind, name)
);
CREATE INDEX idx_notify_templates_kind ON notify_templates (kind);
