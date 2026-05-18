-- Session store for the v1.3 cookie-based local-auth flow.
--
-- Server-side sessions (cookie holds the opaque session ID, all
-- subject data lives here). Chose this over JWT-in-cookie because:
--   1. revocation is a single DELETE — JWTs require an extra denylist
--   2. extending a session's TTL doesn't require re-signing
--   3. operator forensics + audit get a real row to look at
--
-- csrf_token is per-session, surfaces via the auth-required handler
-- response chrome (template variable), and the double-submit cookie
-- middleware compares the cookie value vs the form/header value.

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,              -- random 32-byte hex, stored as cookie value
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT NOT NULL,                 -- random 32-byte hex
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    user_agent      TEXT,                          -- audit only
    ip              TEXT                           -- audit only
);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
