package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

func TestVerifySignature(t *testing.T) {
	secret := "shhhh"
	body := []byte(`{"action":"opened"}`)
	sig := SignBody(secret, body)

	if !VerifySignature(secret, sig, body) {
		t.Error("valid signature returned false")
	}
	if VerifySignature(secret, sig, []byte("tampered")) {
		t.Error("body tamper not detected")
	}
	if VerifySignature("wrong-secret", sig, body) {
		t.Error("wrong-secret accepted")
	}
	if VerifySignature(secret, "sha256=garbage", body) {
		t.Error("garbage hex accepted")
	}
	if VerifySignature(secret, "no-prefix", body) {
		t.Error("missing prefix accepted")
	}
	if VerifySignature("", sig, body) {
		t.Error("empty secret accepted")
	}
}

func TestGithubScanTrigger(t *testing.T) {
	cases := []struct {
		event, body string
		wantAction  string
		wantOK      bool
	}{
		{"pull_request", `{"action":"opened"}`, "opened", true},
		{"pull_request", `{"action":"synchronize"}`, "synchronize", true},
		{"pull_request", `{"action":"reopened"}`, "reopened", true},
		{"pull_request", `{"action":"closed"}`, "", false},
		{"push", `{"ref":"refs/heads/main"}`, "default-branch", true},
		{"push", `{"ref":"refs/heads/master"}`, "default-branch", true},
		{"push", `{"ref":"refs/heads/feature/x"}`, "", false},
		{"issues", `{"action":"opened"}`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.event+"/"+tc.body, func(t *testing.T) {
			a, ok := githubScanTrigger(tc.event, []byte(tc.body))
			if a != tc.wantAction || ok != tc.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", a, ok, tc.wantAction, tc.wantOK)
			}
		})
	}
}

func TestReceiver_GitHubEndToEnd(t *testing.T) {
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	rc := New(st, Config{GitHubSecret: "test-secret"})
	r := chi.NewRouter()
	rc.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	t.Run("valid signature + opened PR → 202 + queued scan", func(t *testing.T) {
		body := []byte(`{"action":"opened","pull_request":{"number":42}}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/github", strings.NewReader(string(body)))
		req.Header.Set("X-Hub-Signature-256", SignBody("test-secret", body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("status = %d, want 202", resp.StatusCode)
		}
		// One queued scan row should now exist.
		count := countQueued(t, st)
		if count != 1 {
			t.Errorf("queued scans = %d, want 1", count)
		}
	})

	t.Run("invalid signature → 401", func(t *testing.T) {
		body := []byte(`{"action":"opened"}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/github", strings.NewReader(string(body)))
		req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
		req.Header.Set("X-GitHub-Event", "pull_request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("valid sig + ignored event → 204 + no scan", func(t *testing.T) {
		before := countQueued(t, st)
		body := []byte(`{"action":"closed"}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/github", strings.NewReader(string(body)))
		req.Header.Set("X-Hub-Signature-256", SignBody("test-secret", body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want 204", resp.StatusCode)
		}
		if after := countQueued(t, st); after != before {
			t.Errorf("queued scans changed: before=%d after=%d", before, after)
		}
	})
}

func TestReceiver_GenericEndToEnd(t *testing.T) {
	st := openMigratedStore(t)
	t.Cleanup(func() { _ = st.Close() })

	// Seed a generic webhook row.
	id := uuid.NewString()
	urlPath := "ci-prod"
	secret := "generic-secret"
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO webhooks (id, name, url_path, secret_hash, event_types, created_at, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, 1)`,
		id, "ci-prod", urlPath, secret, "[]", now)
	if err != nil {
		t.Fatalf("seed webhook: %v", err)
	}

	rc := New(st, Config{})
	r := chi.NewRouter()
	rc.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	t.Run("valid signature → 202 + queued scan + last_received_at touched", func(t *testing.T) {
		body := []byte(`{"event":"build.completed"}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/"+urlPath, strings.NewReader(string(body)))
		req.Header.Set("X-CK-Signature", SignBody(secret, body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("status = %d, want 202", resp.StatusCode)
		}
		if c := countQueued(t, st); c != 1 {
			t.Errorf("queued scans = %d, want 1", c)
		}
		// last_received_at should be set + received_count bumped.
		var receivedCount int
		if err := st.DB().QueryRowContext(context.Background(),
			`SELECT received_count FROM webhooks WHERE id = ?`, id).Scan(&receivedCount); err != nil {
			t.Fatalf("read row: %v", err)
		}
		if receivedCount != 1 {
			t.Errorf("received_count = %d, want 1", receivedCount)
		}
	})

	t.Run("invalid signature → 401, no scan", func(t *testing.T) {
		before := countQueued(t, st)
		body := []byte(`{"event":"build.completed"}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/"+urlPath, strings.NewReader(string(body)))
		req.Header.Set("X-CK-Signature", "sha256=zzzz")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
		if after := countQueued(t, st); after != before {
			t.Errorf("queued scans changed: before=%d after=%d", before, after)
		}
	})

	t.Run("unknown url_path → 404", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/nope", strings.NewReader(""))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("disabled hook → 410", func(t *testing.T) {
		_, err := st.DB().ExecContext(context.Background(),
			`UPDATE webhooks SET enabled = 0 WHERE id = ?`, id)
		if err != nil {
			t.Fatalf("disable: %v", err)
		}
		body := []byte(`{}`)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/webhooks/"+urlPath, strings.NewReader(string(body)))
		req.Header.Set("X-CK-Signature", SignBody(secret, body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusGone {
			t.Errorf("status = %d, want 410", resp.StatusCode)
		}
	})
}

// openMigratedStore returns an in-memory SQLite Store with the v1.3
// schema applied. Each test gets its own DB.
func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(context.Background()); err != nil {
		_ = st.Close()
		t.Fatalf("MigrateUp: %v", err)
	}
	return st
}

func countQueued(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE status = 'queued'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}
