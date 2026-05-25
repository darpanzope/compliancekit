-- v1.14 phase 7 — revocable live-share links.
--
-- One row per share. Recipient gets a URL of the form
-- /shared/{token}; the daemon trades the token for a read-only
-- dashboard render with the watermark_recipient stamped on every
-- page. expires_at + revoked_at gate the trade — past either one,
-- the lookup returns 410 Gone.

CREATE TABLE shared_links (
    token                TEXT PRIMARY KEY,        -- url-safe random
    dashboard_id         TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    created_by_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at           TEXT NOT NULL,
    expires_at           TEXT,                    -- NULL = no expiry
    revoked_at           TEXT,
    watermark_recipient  TEXT NOT NULL DEFAULT '',
    view_count           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_shared_links_dashboard ON shared_links (dashboard_id);
CREATE INDEX idx_shared_links_expires ON shared_links (expires_at);
