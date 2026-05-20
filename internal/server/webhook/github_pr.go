package webhook

// v1.8 phase 6 — GitHub PR-comment two-way sync.
//
// When the outbound v0.17 github-pr sink posts a per-scan summary
// onto a PR, it writes one row per finding into github_pr_mapping.
// Inbound issue_comment events on that PR resolve back to the set
// of fingerprints via this same mapping; each reply lands as a
// compliancekit comment on every finding that PR-comment referenced.
//
// The fan-out lets operators carry a single conversation on the PR
// thread and have it propagated to every finding in the dispatch —
// matching how teams already discuss findings in code review.
//
// Mapping inserts on the outbound side are deferred to v1.8.x; this
// phase ships the inbound + the mapping table so v1.8.x can wire it
// without a second migration.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// handleGitHubIssueComment processes a verified issue_comment event.
// Currently handles action=created (new comment) only; edited/deleted
// are deferred — operators don't typically expect compliancekit to
// rewrite history when a reviewer edits their PR comment.
func (rc *Receiver) handleGitHubIssueComment(w http.ResponseWriter, r *http.Request, body []byte) {
	var env struct {
		Action string `json:"action"`
		Issue  struct {
			Number      int `json:"number"`
			PullRequest *struct {
				URL string `json:"url"`
			} `json:"pull_request"`
		} `json:"issue"`
		Comment struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"comment"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if env.Action != "created" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Only PR comments (not regular issue comments) — issue.pull_request
	// is non-nil for PR comments per GitHub's REST schema.
	if env.Issue.PullRequest == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Don't echo compliancekit's own outbound posts back as inbound
	// comments. The v0.17 sink posts as the configured bot account;
	// operators can drop the "compliancekit" check easily by
	// configuring the bot to a distinct login, but we still strip the
	// obvious "[bot]" suffix.
	if strings.HasSuffix(env.Comment.User.Login, "[bot]") {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	fps, err := rc.lookupGitHubPR(r.Context(), env.Repository.FullName, env.Issue.Number)
	if err != nil || len(fps) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	commentBody := "[GitHub reply by @" + env.Comment.User.Login + "]\n\n" + env.Comment.Body
	for _, fp := range fps {
		_, err := rc.commentsRepo().Add(r.Context(), fp, "", commentBody, comments.AddOptions{
			Source: comments.SourceGitHubPR,
			// Per-fingerprint suffix so the same PR-comment fanned out
			// across multiple findings still uniques on (source,
			// external_id) — preserves redelivery dedup per finding.
			ExternalID: env.Repository.FullName + ":" + strconv.FormatInt(env.Comment.ID, 10) + ":" + fp,
		})
		if err != nil {
			// Likely a unique-constraint violation on the redelivery
			// path — skip and continue with the next fingerprint.
			continue
		}
		_, _ = rc.activitiesRepo().Record(r.Context(), fp, collab.ActivityCommentAdded, collab.RecordOptions{
			ActorSource: collab.ActorGitHubPR,
			Metadata: map[string]any{
				"repo":         env.Repository.FullName,
				"pr_number":    env.Issue.Number,
				"comment_id":   env.Comment.ID,
				"github_login": env.Comment.User.Login,
			},
		})
	}
	w.WriteHeader(http.StatusOK)
}

// lookupGitHubPR returns every fingerprint mapped to the (repo, PR)
// pair. Empty slice means the daemon never posted a comment on that
// PR (the inbound reply isn't ours to ingest).
func (rc *Receiver) lookupGitHubPR(ctx context.Context, repo string, prNumber int) ([]string, error) {
	q := "SELECT DISTINCT fingerprint FROM github_pr_mapping WHERE repo = " +
		rc.ph(1) + " AND issue_number = " + rc.ph(2)
	rows, err := rc.store.DB().QueryContext(ctx, q, repo, prNumber)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// PRMapping holds one row in the github_pr_mapping table. The
// outbound github-pr notifier (or its v1.8.x adapter) constructs
// these alongside its post + persists them via PersistPRMapping.
type PRMapping struct {
	Repo        string
	PRNumber    int
	CommentID   int64
	Fingerprint string
}

// PersistPRMapping inserts the (repo, pr, comment_id, fingerprint)
// tuple. Idempotent via the composite PK ON CONFLICT DO NOTHING.
func (rc *Receiver) PersistPRMapping(ctx context.Context, m PRMapping) error {
	q := persistPRMappingSQL(rc.store.Driver())
	_, err := rc.store.DB().ExecContext(ctx, q,
		m.Repo, m.PRNumber, m.CommentID, m.Fingerprint, time.Now().UTC().Format(time.RFC3339))
	return err
}

func persistPRMappingSQL(driver store.Driver) string {
	if driver == store.DriverPostgres {
		return `INSERT INTO github_pr_mapping (repo, issue_number, comment_id, fingerprint, created_at)
		        VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`
	}
	return `INSERT INTO github_pr_mapping (repo, issue_number, comment_id, fingerprint, created_at)
	        VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`
}
