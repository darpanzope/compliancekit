-- v1.16 phase 4 — VAPID Web Push subscriptions.
--
-- One row per (user, browser/device) tuple. endpoint is the FCM /
-- Mozilla push service URL the browser provisioned during the
-- ServiceWorkerRegistration.pushManager.subscribe() call.
-- p256dh_key + auth_key are the client-side keys the daemon needs
-- to encrypt the push payload per the Web Push spec.
--
-- last_used_at is bumped on every successful send; rows older than
-- a year of inactivity can be pruned by an admin job.

CREATE TABLE push_subscriptions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint      TEXT NOT NULL,
    p256dh_key    TEXT NOT NULL,
    auth_key      TEXT NOT NULL,
    device_label  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_used_at  TEXT NOT NULL,
    UNIQUE (user_id, endpoint)
);
CREATE INDEX idx_push_subscriptions_user ON push_subscriptions (user_id);

-- VAPID keypair lives in app_kv. Single-row 'vapid' key holds a
-- JSON blob { "public": "...", "private": "..." } generated once
-- at first boot and reused forever (rotation invalidates every
-- subscription — out of scope for v1.16, future v1.16.x).
CREATE TABLE IF NOT EXISTS app_kv (
    k          TEXT PRIMARY KEY,
    v          TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
