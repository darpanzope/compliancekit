package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// newTestStore returns a fresh sqlite-backed store with migrations
// applied. Each test gets its own DB file under t.TempDir() so the
// test pool stays parallel-safe.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "ui-setup.db")
	st, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newUIForTests builds a UI bundle wired against a real store + fresh
// auth subjects. The session middleware on the protected route group
// rejects unauthenticated requests, so most wizard-route tests below
// invoke handlers directly to focus on the wizard logic, not auth.
func newUIForTests(t *testing.T) (*UI, *store.Store) {
	t.Helper()
	st := newTestStore(t)
	u := New(st, auth.NewUsers(st), auth.NewSessions(st))
	return u, st
}

// TestSetupEntry_RoutesByDBState walks the three states the wizard
// derives its step from: empty install → welcome; provider configured
// but no scans → scan; provider configured + 1+ scans → /scans.
func TestSetupEntry_RoutesByDBState(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// State 1: no providers enabled → /setup/welcome.
	req := httptest.NewRequest("GET", "/setup", nil)
	rec := httptest.NewRecorder()
	u.setupEntry(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("empty state: status %d want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/setup/welcome" {
		t.Errorf("empty state: Location=%q want /setup/welcome", loc)
	}

	// State 2: enable a provider but leave the scans table empty.
	if err := u.upsertProvider(ctx, "digitalocean", "tok_abc", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}
	req = httptest.NewRequest("GET", "/setup", nil)
	rec = httptest.NewRecorder()
	u.setupEntry(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/setup/scan" {
		t.Errorf("post-auth state: Location=%q want /setup/scan", loc)
	}

	// State 3: queue a scan → wizard is done, "/" routes back to /scans.
	if _, err := u.enqueueWizardScan(ctx, "digitalocean"); err != nil {
		t.Fatalf("enqueueWizardScan: %v", err)
	}
	req = httptest.NewRequest("GET", "/setup", nil)
	rec = httptest.NewRecorder()
	u.setupEntry(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/scans" {
		t.Errorf("complete state: Location=%q want /scans", loc)
	}
	_ = st // keep linter happy
}

// TestUpsertProvider_PersistsAuthStatus confirms a successful probe
// (probeErr=nil) writes last_auth_status='ok' + clears last_auth_error,
// and a failing probe writes 'failed' + records the error string.
func TestUpsertProvider_PersistsAuthStatus(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Successful probe path.
	if err := u.upsertProvider(ctx, "digitalocean", "tok_ok", nil); err != nil {
		t.Fatalf("upsertProvider ok: %v", err)
	}
	var status, errText, cfg string
	row := st.DB().QueryRowContext(ctx,
		`SELECT last_auth_status, COALESCE(last_auth_error,''), config_json
		 FROM providers WHERE id = ?`, "digitalocean")
	if err := row.Scan(&status, &errText, &cfg); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != "ok" || errText != "" {
		t.Errorf("ok-path: status=%q error=%q", status, errText)
	}
	if !strings.Contains(cfg, `"token":"tok_ok"`) {
		t.Errorf("ok-path: config_json missing token: %s", cfg)
	}

	// Failure path overwrites the prior ok status.
	if err := u.upsertProvider(ctx, "digitalocean", "tok_bad",
		errBadToken("401 unauthorized")); err != nil {
		t.Fatalf("upsertProvider fail: %v", err)
	}
	row = st.DB().QueryRowContext(ctx,
		`SELECT last_auth_status, COALESCE(last_auth_error,'')
		 FROM providers WHERE id = ?`, "digitalocean")
	if err := row.Scan(&status, &errText); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != "failed" {
		t.Errorf("fail-path: status=%q want failed", status)
	}
	if !strings.Contains(errText, "401") {
		t.Errorf("fail-path: error=%q expected to contain 401", errText)
	}
}

// TestEnqueueWizardScan_LandsQueuedRow confirms the scan trigger
// writes a row in 'queued' state visible to the worker pool — matching
// what POST /api/v1/scans does, minus the auth + JSON round-trip.
func TestEnqueueWizardScan_LandsQueuedRow(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	id, err := u.enqueueWizardScan(ctx, "digitalocean")
	if err != nil {
		t.Fatalf("enqueueWizardScan: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty scan id")
	}

	var status, source, providers string
	row := st.DB().QueryRowContext(ctx,
		`SELECT status, source, providers_scanned FROM scans WHERE id = ?`, id)
	if err := row.Scan(&status, &source, &providers); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != "queued" {
		t.Errorf("status=%q want queued", status)
	}
	// source is "daemon" because the schema CHECK constraint only
	// allows (cli, daemon, webhook, schedule); the wizard runs inside
	// the daemon process so daemon is the right semantic label.
	if source != "daemon" {
		t.Errorf("source=%q want daemon", source)
	}
	if !strings.Contains(providers, "digitalocean") {
		t.Errorf("providers_scanned=%q expected to contain digitalocean", providers)
	}
}

// TestSetupProviderChoose_RejectsUnknownAndUnavailable guards the
// step-2 → step-3 transition. Catalog-unknown ids and "coming soon"
// providers redirect back to the picker with the right error key, not
// 500 + not a half-configured row.
func TestSetupProviderChoose_RejectsUnknownAndUnavailable(t *testing.T) {
	u, _ := newUIForTests(t)
	cases := []struct {
		provider string
		wantErr  string
	}{
		{"banana-cloud", "unknown"},
		{"aws", "unavailable"},
		{"gcp", "unavailable"},
	}
	for _, c := range cases {
		form := url.Values{}
		form.Set("provider", c.provider)
		req := httptest.NewRequest("POST", "/setup/provider", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		u.setupProviderChoose(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: status %d want 303", c.provider, rec.Code)
		}
		want := "/setup/provider?err=" + c.wantErr
		if loc := rec.Header().Get("Location"); loc != want {
			t.Errorf("%s: Location=%q want %q", c.provider, loc, want)
		}
	}
}

// TestSetupProviderChoose_AcceptsAvailable advances DO (the only MVP
// available provider) to step 3 (auth) with the choice in the query
// string. The daemon doesn't persist anything yet at this transition.
func TestSetupProviderChoose_AcceptsAvailable(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{}
	form.Set("provider", "digitalocean")
	req := httptest.NewRequest("POST", "/setup/provider", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.setupProviderChoose(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/setup/auth?provider=digitalocean" {
		t.Errorf("Location=%q want /setup/auth?provider=digitalocean", loc)
	}
}

// TestSetupRoutesMounted confirms every wizard route is reachable on
// the chi router, so a refactor that drops a Mount call surfaces in
// CI instead of as a 404 in production.
func TestSetupRoutesMounted(t *testing.T) {
	u := New(newTestStore(t),
		auth.NewUsers(newTestStore(t)),
		auth.NewSessions(newTestStore(t)))

	r := chi.NewRouter()
	u.mountSetupRoutes(r)

	wantGET := []string{"/setup", "/setup/welcome", "/setup/provider", "/setup/auth", "/setup/doctor", "/setup/scan"}
	wantPOST := []string{"/setup/provider", "/setup/auth", "/setup/scan"}

	for _, path := range wantGET {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
	for _, path := range wantPOST {
		form := url.Values{"provider": []string{"digitalocean"}, "token": []string{"x"}}
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("POST %s: 404 (route not mounted)", path)
		}
	}
}

// errBadToken is a tiny helper that turns a string into an error
// value for the upsertProvider failure-path test, without dragging
// the real DO probe (which would need network) into this unit test.
func errBadToken(msg string) error { return badTokenErr(msg) }

type badTokenErr string

func (b badTokenErr) Error() string { return string(b) }
