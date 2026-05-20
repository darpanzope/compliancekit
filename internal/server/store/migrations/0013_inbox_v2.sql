-- v1.8 phase 9 — Notification inbox 2.0.
--
-- Extends the v1.4 inbox table with the v1.8 ergonomic columns:
-- snooze, mute, per-event-type prefs. These additions are nullable
-- so existing rows survive the migration unchanged; the
-- application layer treats NULL as "no snooze / no mute / default
-- event_type=alert".
--
-- A new inbox_prefs table holds per-user notification preferences
-- (DND schedule, daily/weekly digest config, per-event-type routing).

ALTER TABLE inbox ADD COLUMN snoozed_until TEXT;             -- NULL = not snoozed
ALTER TABLE inbox ADD COLUMN muted_thread_id TEXT;           -- thread group id for mute-all-similar
ALTER TABLE inbox ADD COLUMN event_type TEXT NOT NULL DEFAULT 'alert';

CREATE INDEX idx_inbox_snoozed ON inbox (user_id, snoozed_until);
CREATE INDEX idx_inbox_event_type ON inbox (event_type);

-- ─── inbox_prefs ────────────────────────────────────────────────────────
-- Per-user notification preferences. event_type rows map a notification
-- class to a delivery routing string:
--   'inbox' — only the in-UI inbox row
--   'email' — additionally send email
--   'silent' — drop entirely
--
-- DND window stored as HH:MM strings (no date — daily-recurring).
-- timezone column holds an IANA name; UTC is the safe default.

CREATE TABLE inbox_prefs (
    user_id          TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    timezone         TEXT NOT NULL DEFAULT 'UTC',
    dnd_start        TEXT,                                     -- 'HH:MM' or NULL
    dnd_end          TEXT,                                     -- 'HH:MM' or NULL
    digest_daily     INTEGER NOT NULL DEFAULT 0,               -- 0/1 boolean
    digest_weekly    INTEGER NOT NULL DEFAULT 0,
    digest_hour      INTEGER NOT NULL DEFAULT 9,               -- 0–23
    digest_weekday   INTEGER NOT NULL DEFAULT 1,               -- 0=Sun .. 6=Sat
    routing_json     TEXT NOT NULL DEFAULT '{}',               -- {"alert":"email","comment":"inbox",...}
    updated_at       TEXT NOT NULL
);
