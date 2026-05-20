-- v1.8 phase 8 — Teams.
--
-- Teams are operator-defined named groupings of users. A team can be
-- assigned to a finding (future phase: rules engine), mentioned in a
-- comment via @team-<slug>, or used as a notification-prefs target.
--
-- Membership is N:N. The created_by_user_id slot records who set
-- the team up — useful for audit_log + deciding who can edit/delete
-- (any admin or the creator).
--
-- slug is the human handle used in @team-<slug> mention syntax;
-- enforced unique and lowercased at the application layer.

CREATE TABLE teams (
    id                  TEXT PRIMARY KEY,
    slug                TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    created_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE team_members (
    team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'lead')),
    added_at    TEXT NOT NULL,
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX idx_team_members_user ON team_members (user_id);
