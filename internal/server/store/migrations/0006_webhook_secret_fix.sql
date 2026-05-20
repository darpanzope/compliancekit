-- v1.5.1 phase 4 — Webhook secret column fix (F19 + F25).
--
-- v1.3 phase 6 shipped the webhooks table with `secret_hash` (bcrypt
-- of the HMAC signing secret). The receiver handler then read that
-- hash and used it directly as the HMAC verification key. A sender
-- HMAC-keys with the plaintext secret; the receiver was keying with
-- the bcrypt hash. Mathematically impossible to produce a valid
-- signature; the route was broken-by-construction.
--
-- Fix: rename `secret_hash` to `secret` (plaintext at-rest). The
-- operator secures the daemon's DB file; this matches how GitHub
-- stores webhook secrets and how the v1.3 --github-webhook-secret
-- flag passes its secret through. Encryption-at-rest is a v1.6+
-- enhancement (would need a daemon-side KEK + KMS option).
--
-- Safe because v1.3-v1.5 has no INSERT INTO webhooks anywhere in
-- production code (verified by grep) — only test fixtures touch
-- this table. No data to migrate.

ALTER TABLE webhooks RENAME COLUMN secret_hash TO secret;
