package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// TestServeUsersCreate_RoundTrip drives the cobra command via its
// SetArgs + Execute path; confirms the user lands in the DB.
func TestServeUsersCreate_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.db")

	cmd := newServeUsersCreateCmd()
	cmd.SetArgs([]string{
		"--email", "alice@example.com",
		"--password", "p@ssw0rd-strong-enough-for-bcrypt",
		"--name", "Alice",
		"--admin",
		"--db", dbPath,
	})
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "created user alice@example.com") {
		t.Errorf("stdout missing success line:\n%s", out.String())
	}

	// Confirm DB row exists.
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = st.Close() }()
	var email string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT email FROM users WHERE email = ?`, "alice@example.com").Scan(&email); err != nil {
		t.Fatalf("query: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("user not in DB: got %q", email)
	}
}

// TestServeUsersCreate_RequiresEmail confirms the validation guard
// fires on empty --email.
func TestServeUsersCreate_RequiresEmail(t *testing.T) {
	tmp := t.TempDir()
	cmd := newServeUsersCreateCmd()
	cmd.SetArgs([]string{
		"--password", "x",
		"--db", filepath.Join(tmp, "test.db"),
	})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--email is required") {
		t.Errorf("expected --email required error, got %v", err)
	}
}

// TestServeTokensIssue_RoundTrip creates a user, issues a token,
// confirms the token row exists with the right scopes.
func TestServeTokensIssue_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.db")

	// Create user first.
	uc := newServeUsersCreateCmd()
	uc.SetArgs([]string{
		"--email", "bob@example.com",
		"--password", "p@ssw0rd-strong",
		"--db", dbPath,
	})
	uc.SetContext(context.Background())
	uc.SetOut(&bytes.Buffer{})
	if err := uc.Execute(); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Issue token.
	tc := newServeTokensIssueCmd()
	tc.SetArgs([]string{
		"--user", "bob@example.com",
		"--scope", "scans:read,findings:read",
		"--name", "ci-token",
		"--db", dbPath,
	})
	tc.SetContext(context.Background())
	var out, errBuf bytes.Buffer
	tc.SetOut(&out)
	tc.SetErr(&errBuf)
	if err := tc.Execute(); err != nil {
		t.Fatalf("issue token: %v", err)
	}

	rawToken := strings.TrimSpace(out.String())
	if !strings.HasPrefix(rawToken, "ck_") {
		t.Errorf("token=%q expected to start with ck_", rawToken)
	}

	// Confirm DB row exists with the scopes.
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = st.Close() }()
	var scopes string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT scopes FROM api_tokens WHERE name = ?`, "ci-token").Scan(&scopes); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.Contains(scopes, "scans:read") || !strings.Contains(scopes, "findings:read") {
		t.Errorf("scopes=%q expected both scopes", scopes)
	}
}

// TestSeedDemoData populates a fresh DB with the demo dataset and
// confirms the row counts.
func TestSeedDemoData(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	st, err := store.OpenSQLite(ctx, filepath.Join(tmp, "demo.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	if err := seedDemoData(ctx, st); err != nil {
		t.Fatalf("seedDemoData: %v", err)
	}

	cases := map[string]int{
		"users":     1,
		"providers": 6, // v1.19 phase 4 — DO/AWS/GCP/K8s enabled + Hetzner/Linux disabled
		"scans":     8, // v1.19 phase 4 — 8 weekly scans
		"inbox":     1,
	}
	for tbl, want := range cases {
		var got int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+tbl).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if got != want {
			t.Errorf("count(%s)=%d want %d", tbl, got, want)
		}
	}

	// v1.19 phase 4 — screenshot-grade dataset: ~500 findings across
	// ~150 resources on an improving trend. Assert order of magnitude
	// (exact counts shift with the RNG/catalog) + that the newest scan
	// carries fewer findings than the oldest.
	var findingCount, resourceCount int
	_ = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&findingCount)
	_ = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM resources`).Scan(&resourceCount)
	if findingCount < 350 {
		t.Errorf("findings = %d, want ~500 (screenshot-grade)", findingCount)
	}
	if resourceCount < 100 {
		t.Errorf("resources = %d, want ~150 (screenshot-grade)", resourceCount)
	}
	var newest, oldest int
	_ = st.DB().QueryRowContext(ctx, `SELECT total_findings FROM scans WHERE id = 'demo-scan-1'`).Scan(&newest)
	_ = st.DB().QueryRowContext(ctx, `SELECT total_findings FROM scans WHERE id = 'demo-scan-8'`).Scan(&oldest)
	if newest >= oldest {
		t.Errorf("improving trend broken: newest scan %d findings >= oldest %d", newest, oldest)
	}

	// Re-running seed is idempotent — counts shouldn't double.
	if err := seedDemoData(ctx, st); err != nil {
		t.Fatalf("second seedDemoData: %v", err)
	}
	for tbl, want := range cases {
		var got int
		_ = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl).Scan(&got)
		if got != want {
			t.Errorf("after re-seed, count(%s)=%d want %d (must be idempotent)", tbl, got, want)
		}
	}
}
