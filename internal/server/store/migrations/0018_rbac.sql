-- v1.12 phase 0 — RBAC core: roles, role_permissions, user_roles.
--
-- Replaces the binary users.is_admin bit (preserved as a backwards-
-- compatible legacy column) with a relational role/permission grid.
-- Each user can carry zero-or-more roles; each role grants zero-or-
-- more (resource, action) tuples. The v1.12 phase 2 scope-gate
-- refactor switches the existing `auth.Scope*` checks to derive their
-- answer from this grid via a default-mapping migration — until then
-- the existing scope checks continue to gate everything and the
-- RBAC tables are read-mostly admin-UI state.
--
-- Built-in roles (is_builtin=1) cannot be deleted; their name and
-- description are stable. Operators add custom roles with whatever
-- permission rows they need.
--
-- Resources + actions enum-equivalent:
--   resources: scans, findings, settings, users, api_tokens, plugins,
--              audit_log, rules, waivers, frameworks, comments
--   actions:   read, write, delete, admin
--
-- The CHECK constraint enforces the enum so a typo in custom-role
-- creation fails fast instead of silently never matching at gate time.

CREATE TABLE roles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    is_builtin      INTEGER NOT NULL DEFAULT 0,   -- 0/1
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_roles_name ON roles (name);

CREATE TABLE role_permissions (
    role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource    TEXT NOT NULL
                    CHECK (resource IN (
                        'scans', 'findings', 'settings', 'users',
                        'api_tokens', 'plugins', 'audit_log',
                        'rules', 'waivers', 'frameworks', 'comments')),
    action      TEXT NOT NULL
                    CHECK (action IN ('read', 'write', 'delete', 'admin')),
    PRIMARY KEY (role_id, resource, action)
);
CREATE INDEX idx_role_permissions_role ON role_permissions (role_id);

CREATE TABLE user_roles (
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id             TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at          TEXT NOT NULL,
    granted_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_user ON user_roles (user_id);
CREATE INDEX idx_user_roles_role ON user_roles (role_id);

-- ─── Built-in roles ──────────────────────────────────────────────────
-- admin   — full grant on every resource (the * superpower role).
-- editor  — write on scans/findings/waivers/comments/rules; read on
--           settings/users/frameworks; no admin anywhere.
-- viewer  — read on all visible resources; no writes, no admin.
-- auditor — read on findings/audit_log/frameworks/waivers; no writes.

INSERT INTO roles (id, name, description, is_builtin, created_at, updated_at) VALUES
    ('role-admin',   'admin',   'Full administrative access to every resource.',        1, '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'),
    ('role-editor',  'editor',  'Read + write on operational resources; no admin.',     1, '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'),
    ('role-viewer',  'viewer',  'Read-only access across the daemon.',                  1, '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'),
    ('role-auditor', 'auditor', 'Read access to findings, audit log, and frameworks.',  1, '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');

-- admin gets every (resource, action) tuple.
INSERT INTO role_permissions (role_id, resource, action) VALUES
    ('role-admin', 'scans',      'read'),  ('role-admin', 'scans',      'write'),  ('role-admin', 'scans',      'delete'),  ('role-admin', 'scans',      'admin'),
    ('role-admin', 'findings',   'read'),  ('role-admin', 'findings',   'write'),  ('role-admin', 'findings',   'delete'),  ('role-admin', 'findings',   'admin'),
    ('role-admin', 'settings',   'read'),  ('role-admin', 'settings',   'write'),  ('role-admin', 'settings',   'delete'),  ('role-admin', 'settings',   'admin'),
    ('role-admin', 'users',      'read'),  ('role-admin', 'users',      'write'),  ('role-admin', 'users',      'delete'),  ('role-admin', 'users',      'admin'),
    ('role-admin', 'api_tokens', 'read'),  ('role-admin', 'api_tokens', 'write'),  ('role-admin', 'api_tokens', 'delete'),  ('role-admin', 'api_tokens', 'admin'),
    ('role-admin', 'plugins',    'read'),  ('role-admin', 'plugins',    'write'),  ('role-admin', 'plugins',    'delete'),  ('role-admin', 'plugins',    'admin'),
    ('role-admin', 'audit_log',  'read'),  ('role-admin', 'audit_log',  'write'),  ('role-admin', 'audit_log',  'delete'),  ('role-admin', 'audit_log',  'admin'),
    ('role-admin', 'rules',      'read'),  ('role-admin', 'rules',      'write'),  ('role-admin', 'rules',      'delete'),  ('role-admin', 'rules',      'admin'),
    ('role-admin', 'waivers',    'read'),  ('role-admin', 'waivers',    'write'),  ('role-admin', 'waivers',    'delete'),  ('role-admin', 'waivers',    'admin'),
    ('role-admin', 'frameworks', 'read'),  ('role-admin', 'frameworks', 'write'),  ('role-admin', 'frameworks', 'delete'),  ('role-admin', 'frameworks', 'admin'),
    ('role-admin', 'comments',   'read'),  ('role-admin', 'comments',   'write'),  ('role-admin', 'comments',   'delete'),  ('role-admin', 'comments',   'admin');

-- editor — read + write on operational resources; read on settings/users/frameworks.
INSERT INTO role_permissions (role_id, resource, action) VALUES
    ('role-editor', 'scans',      'read'),  ('role-editor', 'scans',      'write'),
    ('role-editor', 'findings',   'read'),  ('role-editor', 'findings',   'write'),
    ('role-editor', 'rules',      'read'),  ('role-editor', 'rules',      'write'),
    ('role-editor', 'waivers',    'read'),  ('role-editor', 'waivers',    'write'),
    ('role-editor', 'comments',   'read'),  ('role-editor', 'comments',   'write'),
    ('role-editor', 'settings',   'read'),
    ('role-editor', 'users',      'read'),
    ('role-editor', 'frameworks', 'read'),
    ('role-editor', 'audit_log',  'read'),
    ('role-editor', 'plugins',    'read'),
    ('role-editor', 'api_tokens', 'read');

-- viewer — read across the board, no writes.
INSERT INTO role_permissions (role_id, resource, action) VALUES
    ('role-viewer', 'scans',      'read'),
    ('role-viewer', 'findings',   'read'),
    ('role-viewer', 'rules',      'read'),
    ('role-viewer', 'waivers',    'read'),
    ('role-viewer', 'comments',   'read'),
    ('role-viewer', 'settings',   'read'),
    ('role-viewer', 'users',      'read'),
    ('role-viewer', 'frameworks', 'read'),
    ('role-viewer', 'plugins',    'read'),
    ('role-viewer', 'api_tokens', 'read');

-- auditor — read on the audit-relevant slice only.
INSERT INTO role_permissions (role_id, resource, action) VALUES
    ('role-auditor', 'findings',   'read'),
    ('role-auditor', 'audit_log',  'read'),
    ('role-auditor', 'frameworks', 'read'),
    ('role-auditor', 'waivers',    'read'),
    ('role-auditor', 'comments',   'read');

-- Backfill: every existing user with is_admin=1 gets the admin role.
-- Non-admin users get no role until phase 2 finalizes the default
-- mapping (the legacy scope gates still gate them in the interim).
INSERT INTO user_roles (user_id, role_id, granted_at)
SELECT id, 'role-admin', '1970-01-01T00:00:00Z' FROM users WHERE is_admin = 1;
