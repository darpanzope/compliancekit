-- v1.8 phase 6 — GitHub PR-comment two-way sync.
--
-- The v0.17 outbound github-pr sink already posts ONE summary
-- comment per scan dispatch (anti-spam choice from v0.17). v1.8
-- phase 6 layers two-way sync on that flow: when an operator
-- replies on the PR (issue-comment), the daemon picks it up via
-- the existing /webhooks/github inbound path + materialises it as
-- a compliancekit comment on each finding the original PR-comment
-- mentioned.
--
-- The mapping is many-fingerprints-per-PR-comment: one PR summary
-- references every finding in the dispatch, so a single inbound
-- reply on that comment can fan out to multiple finding threads.
--
-- The composite PK is (repo, issue_number, comment_id) — repo is
-- "<owner>/<name>"; issue_number is the PR number (GitHub treats
-- PRs and issues as the same numbering space); comment_id is the
-- review/issue comment id. A NULL comment_id (top-level PR
-- description) is allowed via the COALESCE'd index.

CREATE TABLE github_pr_mapping (
    repo            TEXT NOT NULL,
    issue_number    INTEGER NOT NULL,
    comment_id      INTEGER NOT NULL DEFAULT 0,    -- 0 = the PR body itself
    fingerprint     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (repo, issue_number, comment_id, fingerprint)
);
CREATE INDEX idx_github_pr_mapping_fingerprint ON github_pr_mapping (fingerprint);
CREATE INDEX idx_github_pr_mapping_pr ON github_pr_mapping (repo, issue_number);
