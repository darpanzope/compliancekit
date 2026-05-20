package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// TestGitHubPRMapping_FanOut verifies that when an issue_comment
// event arrives on a PR with two mapped findings, both fingerprints
// receive the comment.
func TestGitHubPRMapping_FanOut(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	rc := New(st, Config{GitHubSecret: "shh"})

	// Seed the mapping: PR #42 in acme/repo has two findings linked.
	if err := rc.PersistPRMapping(ctx, PRMapping{
		Repo: "acme/repo", PRNumber: 42, CommentID: 1, Fingerprint: "fp-a",
	}); err != nil {
		t.Fatalf("PersistPRMapping fp-a: %v", err)
	}
	if err := rc.PersistPRMapping(ctx, PRMapping{
		Repo: "acme/repo", PRNumber: 42, CommentID: 1, Fingerprint: "fp-b",
	}); err != nil {
		t.Fatalf("PersistPRMapping fp-b: %v", err)
	}

	r := chi.NewRouter()
	rc.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	body := []byte(`{
		"action": "created",
		"issue":  { "number": 42, "pull_request": { "url": "https://api.github.com/repos/acme/repo/pulls/42" } },
		"comment": { "id": 99, "body": "Looks fine to me", "user": { "login": "reviewer" } },
		"repository": { "full_name": "acme/repo" }
	}`)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "issue_comment")
	mac := hmac.New(sha256.New, []byte("shh"))
	mac.Write(body)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Both fingerprints should have one comment each.
	for _, fp := range []string{"fp-a", "fp-b"} {
		var n int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM comments WHERE finding_fingerprint = ?`, fp).Scan(&n); err != nil {
			t.Fatalf("count comments(%s): %v", fp, err)
		}
		if n != 1 {
			t.Errorf("comments on %s = %d, want 1", fp, n)
		}
	}
}

// TestGitHubPRMapping_NoMappingNoCommentary confirms an
// issue_comment on a PR we never tracked is a no-op.
func TestGitHubPRMapping_NoMappingNoCommentary(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	rc := New(st, Config{GitHubSecret: "shh"})
	r := chi.NewRouter()
	rc.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	body := []byte(`{
		"action": "created",
		"issue":  { "number": 999, "pull_request": { "url": "x" } },
		"comment": { "id": 1, "body": "hi", "user": { "login": "alice" } },
		"repository": { "full_name": "nope/nope" }
	}`)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "issue_comment")
	mac := hmac.New(sha256.New, []byte("shh"))
	mac.Write(body)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}
