-- v1.14 phase 8 — audit-pack profile builder.
--
-- An audit pack is the bundle of artifacts an auditor receives:
-- findings.csv, vulnerabilities.csv, poam.oscal.json, waivers.json,
-- one or more dashboard PDFs. A profile is the operator-saved
-- selection of which artifacts to include for a given audit.
--
-- artifacts_json is a JSON array of strings (artifact IDs from the
-- canonical set). dashboards_json is a JSON array of dashboard IDs
-- whose PDF renders to include.

CREATE TABLE audit_pack_profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    artifacts_json  TEXT NOT NULL DEFAULT '[]',
    dashboards_json TEXT NOT NULL DEFAULT '[]',
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_audit_pack_profiles_name ON audit_pack_profiles (name);
