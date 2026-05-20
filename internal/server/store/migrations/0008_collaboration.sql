-- v1.8 phase 0 — Collaboration & workflow foundation.
--
-- Findings stop being a wall of read-only text and become a conversation:
-- per-finding markdown comments, per-finding assignees, per-resource owners
-- + followers, and a chronological per-finding activity stream. Every
-- subsequent v1.8 phase (Slack reply-in-thread, PR two-way sync, Jira/Linear
-- two-way, mentions, inbox 2.0) reads or writes one of these tables.
--
-- Identity model:
--   • Comments + activity + assignment join on Finding.Fingerprint() (the
--     stable (check_id, resource.id, status) hash) rather than findings.id.
--     A finding may appear in scan A then again in scan B with a different
--     row-id; the operator's running conversation should follow the
--     fingerprint, not get reset every scan.
--   • Resource owner + followers join on resources.id (the resource itself
--     is durable across scans).
--
-- Latest-wins shape:
--   • finding_assignment is keyed on the fingerprint — at most one row per
--     fingerprint, mutated in place. History lives in finding_activity.
--   • resource_owner is keyed on the resource_id — same pattern.
--   • resource_follower is a join table (composite PK).
--
-- Activity stream:
--   The finding_activity table stores one row per event regardless of source
--   (state change, comment added, waiver applied, scan re-ran touching this
--   fingerprint, webhook event mentioning the resource). The activity feed
--   in the UI is a straight SELECT ORDER BY created_at DESC.
--
-- Source-of-truth note: comments[].body is the canonical markdown source the
-- author wrote; body_html is the goldmark-rendered HTML cached for list
-- rendering. Edit history is folded into a single edited_at column; we don't
-- retain prior versions at v1.8 (per the issue scope; v1.9 may revisit).

-- ─── comments ───────────────────────────────────────────────────────────
-- One row per comment on a finding. finding_fingerprint joins across scans.
-- author_user_id ON DELETE SET NULL so removing a user doesn't erase the
-- conversation; the UI renders "deleted user" for null actors.
CREATE TABLE comments (
    id                      TEXT PRIMARY KEY,
    finding_fingerprint     TEXT NOT NULL,
    author_user_id          TEXT REFERENCES users(id) ON DELETE SET NULL,
    body                    TEXT NOT NULL,              -- markdown source
    body_html               TEXT NOT NULL DEFAULT '',   -- goldmark-rendered, sanitized
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    edited_at               TEXT,                       -- NULL = never edited
    source                  TEXT NOT NULL DEFAULT 'ui'  -- 'ui' / 'slack' / 'teams' / 'github-pr' / 'jira' / 'linear'
                                CHECK (source IN ('ui', 'slack', 'teams', 'github-pr', 'jira', 'linear')),
    external_id             TEXT,                       -- inbound sink's native id (slack ts, gh comment id, jira comment id)
    UNIQUE (source, external_id)                        -- prevents double-ingest from a sink redelivery
);
CREATE INDEX idx_comments_finding_fp ON comments (finding_fingerprint);
CREATE INDEX idx_comments_author ON comments (author_user_id);
CREATE INDEX idx_comments_created_at ON comments (created_at);

-- ─── finding_activity ───────────────────────────────────────────────────
-- Chronological activity log keyed by fingerprint. Kind discriminates the
-- payload. metadata_json carries kind-specific detail (e.g. for
-- 'state_changed': {"from": "fail", "to": "pass"}; for 'comment_added':
-- {"comment_id": "..."}; for 'assigned': {"assignee_user_id": "..."}).
CREATE TABLE finding_activity (
    id                      TEXT PRIMARY KEY,
    finding_fingerprint     TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    kind                    TEXT NOT NULL CHECK (kind IN (
        'state_changed', 'comment_added', 'comment_edited',
        'waiver_applied', 'waiver_revoked', 'scan_ran',
        'webhook_event', 'assigned', 'unassigned',
        'owner_changed', 'follower_added', 'follower_removed'
    )),
    actor_user_id           TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_source            TEXT NOT NULL DEFAULT 'ui'   -- 'ui' / 'engine' / 'slack' / 'github-pr' / 'jira' / 'linear' / 'webhook'
                                CHECK (actor_source IN ('ui', 'engine', 'slack', 'teams', 'github-pr', 'jira', 'linear', 'webhook')),
    metadata_json           TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_finding_activity_fp ON finding_activity (finding_fingerprint, created_at);
CREATE INDEX idx_finding_activity_actor ON finding_activity (actor_user_id);

-- ─── finding_assignment ─────────────────────────────────────────────────
-- One assignee per fingerprint. Mutated in place; history lives in
-- finding_activity via 'assigned' + 'unassigned' rows.
CREATE TABLE finding_assignment (
    finding_fingerprint     TEXT PRIMARY KEY,
    assignee_user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by_user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    assigned_at             TEXT NOT NULL
);
CREATE INDEX idx_finding_assignment_user ON finding_assignment (assignee_user_id);

-- ─── resource_owner ─────────────────────────────────────────────────────
-- One owner per resource. resources.id is the join key (resources table
-- from migration 0001). Updated in place per the same latest-wins pattern.
CREATE TABLE resource_owner (
    resource_id             TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    owner_user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by_user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    assigned_at             TEXT NOT NULL
);
CREATE INDEX idx_resource_owner_user ON resource_owner (owner_user_id);

-- ─── resource_follower ──────────────────────────────────────────────────
-- Many-to-many. Operators opt in to "any finding on this resource notifies
-- me" — the v0.17 sinks + the inbox 2.0 producer consult this table when
-- a finding event fires.
CREATE TABLE resource_follower (
    resource_id             TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at              TEXT NOT NULL,
    PRIMARY KEY (resource_id, user_id)
);
CREATE INDEX idx_resource_follower_user ON resource_follower (user_id);
