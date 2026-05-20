-- v1.6 phase 9 — F21 carryover from the v1.5.1 audit.
--
-- GitHub webhook receivers compute a rich trigger string
-- ("github.pull_request.opened" / "github.push.default-branch" /
-- "webhook:<row-id>") at request time + immediately discard it
-- via enqueueScan(_, source). The scans table has no slot for
-- per-row trigger metadata — only a coarse `source` column
-- (cli / daemon / schedule / webhook). Operators looking at
-- /scans can't distinguish a PR-sync from a push-to-main from
-- a generic webhook trip.
--
-- Add a nullable `trigger` column so the receiver can persist
-- the computed value. NULL = no specific trigger (manual scan,
-- CLI push, etc.). The /scans + /scans/{id} render paths
-- conditionally surface it next to the source badge.

ALTER TABLE scans ADD COLUMN trigger TEXT;
