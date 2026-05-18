-- Initial schema for the compliancekit serve-mode store.
--
-- Eleven tables cover the daemon's full persistent state for v1.3:
--   scans + findings + resources       — historical scan record
--   providers + checks_state           — config (enabled providers, per-check toggles)
--   waivers                            — operator-declared exceptions
--   users + api_tokens                 — auth subjects
--   schedules                          — cron-driven scans
--   webhooks                           — inbound receivers
--   audit_log                          — who-did-what append-only trail
--
-- IDs are TEXT (uuid4) for portability across SQLite + Postgres.
-- Timestamps are TEXT (ISO-8601 / RFC-3339) — SQLite's TIMESTAMP type
-- is just TEXT under the hood, but the explicit choice keeps the
-- schema portable to Postgres without a per-driver translation.
--
-- All FKs use ON DELETE CASCADE for child-of-scan rows (findings,
-- resources rows attributed to a single scan); user/token references
-- use ON DELETE SET NULL to preserve audit history when an actor is
-- removed.

-- ─── scans ───────────────────────────────────────────────────────
CREATE TABLE scans (
    id                      TEXT PRIMARY KEY,
    created_at              TEXT NOT NULL,
    started_at              TEXT,
    finished_at             TEXT,
    source                  TEXT NOT NULL CHECK (source IN ('cli', 'daemon', 'webhook', 'schedule')),
    status                  TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'canceled')),
    providers_scanned       TEXT NOT NULL DEFAULT '[]',         -- JSON array
    frameworks_scanned      TEXT NOT NULL DEFAULT '[]',         -- JSON array
    score                   INTEGER,
    coverage                INTEGER,
    total_findings          INTEGER NOT NULL DEFAULT 0,
    actionable_findings     INTEGER NOT NULL DEFAULT 0,
    duration_ms             INTEGER,
    raw_meta                TEXT,                                -- full envelope from CLI uploads
    triggered_by_user_id    TEXT,
    triggered_by_token_id   TEXT,
    error_message           TEXT
);
CREATE INDEX idx_scans_created_at ON scans (created_at);
CREATE INDEX idx_scans_status ON scans (status);
CREATE INDEX idx_scans_source ON scans (source);

-- ─── findings ───────────────────────────────────────────────────
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint         TEXT NOT NULL,                           -- joins to baseline + prior scans
    check_id            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status              TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'skip', 'error')),
    provider            TEXT NOT NULL,                           -- prefix of resource.type
    resource_id         TEXT NOT NULL,
    resource_name       TEXT NOT NULL,
    resource_type       TEXT NOT NULL,
    message             TEXT,
    framework_ids       TEXT NOT NULL DEFAULT '[]',              -- JSON array of framework IDs
    first_seen_at       TEXT NOT NULL,                           -- earliest scan where this fingerprint appears
    last_seen_at        TEXT NOT NULL,                           -- most recent
    created_at          TEXT NOT NULL
);
-- Hot-path indexes for the v1.5 explorer's filter combinations.
CREATE INDEX idx_findings_scan_id ON findings (scan_id);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_status ON findings (status);
CREATE INDEX idx_findings_provider ON findings (provider);
CREATE INDEX idx_findings_resource_type ON findings (resource_type);
CREATE INDEX idx_findings_check_id ON findings (check_id);
CREATE INDEX idx_findings_resource_id ON findings (resource_id);

-- ─── resources ──────────────────────────────────────────────────
-- One row per distinct resource ID ever seen. Updates last_seen on
-- each scan; v1.5's resource map and inventory table read from here.
CREATE TABLE resources (
    id                      TEXT PRIMARY KEY,                    -- Finding.Resource.ID
    name                    TEXT NOT NULL,
    type                    TEXT NOT NULL,
    provider                TEXT NOT NULL,
    first_seen_at           TEXT NOT NULL,
    last_seen_at            TEXT NOT NULL,
    last_seen_scan_id       TEXT REFERENCES scans(id) ON DELETE SET NULL,
    attrs                   TEXT NOT NULL DEFAULT '{}'           -- JSON object
);
CREATE INDEX idx_resources_provider ON resources (provider);
CREATE INDEX idx_resources_type ON resources (type);
CREATE INDEX idx_resources_last_seen ON resources (last_seen_at);

-- ─── providers ──────────────────────────────────────────────────
CREATE TABLE providers (
    id                      TEXT PRIMARY KEY,                    -- 'aws', 'digitalocean', 'k8s', 'linux', ...
    enabled                 INTEGER NOT NULL DEFAULT 0,          -- 0/1 boolean
    config_json             TEXT NOT NULL DEFAULT '{}',          -- provider-specific settings
    last_auth_check_at      TEXT,
    last_auth_status        TEXT CHECK (last_auth_status IN ('ok', 'failed', 'unknown')),
    last_auth_error         TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

-- ─── checks_state ───────────────────────────────────────────────
-- Per-check enabled/disabled override. Absence = use shipped default
-- (which is "enabled"). Rows only exist for checks the operator has
-- explicitly toggled or annotated.
CREATE TABLE checks_state (
    check_id                TEXT PRIMARY KEY,
    enabled                 INTEGER NOT NULL DEFAULT 1,          -- 0/1
    disabled_reason         TEXT,
    disabled_by_user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    disabled_at             TEXT,
    updated_at              TEXT NOT NULL
);

-- ─── waivers ────────────────────────────────────────────────────
-- Same shape as compliancekit's existing waivers.yaml + an `id` for
-- UI editing + creator + creation timestamp for audit.
CREATE TABLE waivers (
    id                      TEXT PRIMARY KEY,
    check_id                TEXT NOT NULL,
    resource_id             TEXT NOT NULL,                       -- supports glob '*' per ADR-013
    reason                  TEXT NOT NULL,
    approver                TEXT NOT NULL,
    created_by_user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    expires_at              TEXT,                                -- NULL = no expiry
    revoked_at              TEXT
);
CREATE INDEX idx_waivers_check_id ON waivers (check_id);
CREATE INDEX idx_waivers_resource_id ON waivers (resource_id);
CREATE INDEX idx_waivers_expires_at ON waivers (expires_at);

-- ─── users ──────────────────────────────────────────────────────
-- Local-auth (email + bcrypt password_hash) AND OIDC users share
-- this table. oidc_subject + oidc_provider are NULL for local-only
-- accounts; password_hash is NULL for OIDC-only accounts.
CREATE TABLE users (
    id                      TEXT PRIMARY KEY,
    email                   TEXT NOT NULL UNIQUE,
    display_name            TEXT,
    password_hash           TEXT,                                -- bcrypt; NULL for OIDC-only
    oidc_subject            TEXT,
    oidc_provider           TEXT,                                -- 'google', 'github', 'okta', 'custom'
    is_admin                INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT NOT NULL,
    last_login_at           TEXT,
    UNIQUE (oidc_provider, oidc_subject)
);

-- ─── api_tokens ─────────────────────────────────────────────────
-- Operator-issued tokens for CI / scripting. token_hash is bcrypt of
-- the actual token value (the plaintext is shown ONCE at issue time);
-- prefix carries the first 8 chars for the operator to identify a
-- token in lists without exposing the secret.
CREATE TABLE api_tokens (
    id                      TEXT PRIMARY KEY,
    user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    token_hash              TEXT NOT NULL UNIQUE,
    prefix                  TEXT NOT NULL,                       -- 'ck_xxxxxxxx' first 8 chars
    scopes                  TEXT NOT NULL DEFAULT '[]',          -- JSON array: 'scans:read','findings:write',...
    created_at              TEXT NOT NULL,
    last_used_at            TEXT,
    expires_at              TEXT,
    revoked_at              TEXT
);
CREATE INDEX idx_api_tokens_user_id ON api_tokens (user_id);
CREATE INDEX idx_api_tokens_prefix ON api_tokens (prefix);

-- ─── schedules ──────────────────────────────────────────────────
-- Cron-driven scans. The worker pool from phase 8 polls this table
-- + spawns scan jobs at next_run_at.
CREATE TABLE schedules (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    cron_expr               TEXT NOT NULL,                       -- standard 5-field cron
    timezone                TEXT NOT NULL DEFAULT 'UTC',         -- IANA tz database
    providers               TEXT NOT NULL DEFAULT '[]',          -- JSON array; empty = all enabled
    frameworks              TEXT NOT NULL DEFAULT '[]',          -- JSON array; empty = all configured
    profile                 TEXT,                                -- optional profile name
    created_by_user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    last_run_at             TEXT,
    last_run_scan_id        TEXT REFERENCES scans(id) ON DELETE SET NULL,
    next_run_at             TEXT NOT NULL,
    enabled                 INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_schedules_next_run_at ON schedules (next_run_at) WHERE enabled = 1;

-- ─── webhooks ───────────────────────────────────────────────────
-- Inbound webhook receivers; secret_hash is the bcrypt of the HMAC
-- signing secret the sender presents.
CREATE TABLE webhooks (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    url_path                TEXT NOT NULL UNIQUE,                -- '/webhooks/:id'
    secret_hash             TEXT NOT NULL,
    event_types             TEXT NOT NULL DEFAULT '[]',          -- JSON array; '*' for all
    created_by_user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    last_received_at        TEXT,
    received_count          INTEGER NOT NULL DEFAULT 0,
    enabled                 INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_webhooks_url_path ON webhooks (url_path);

-- ─── audit_log ──────────────────────────────────────────────────
-- Append-only. Every config mutation, scan trigger, waiver change,
-- token issuance, login + logout lands here. The v1.4 audit UI
-- (#26 phase 11) reads from this table.
CREATE TABLE audit_log (
    id                      TEXT PRIMARY KEY,
    created_at              TEXT NOT NULL,
    actor_user_id           TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_token_id          TEXT REFERENCES api_tokens(id) ON DELETE SET NULL,
    actor_ip                TEXT,                                -- real-IP from middleware
    action                  TEXT NOT NULL,                       -- 'scan.trigger', 'waiver.add', ...
    entity_type             TEXT,                                -- 'scan', 'waiver', 'check', 'token', 'user', 'webhook'
    entity_id               TEXT,
    metadata_json           TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_actor_user_id ON audit_log (actor_user_id);
CREATE INDEX idx_audit_log_entity ON audit_log (entity_type, entity_id);
