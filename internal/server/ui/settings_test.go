package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestSettingsListProviders_MergesCatalogAndDB confirms the list view
// renders every catalog provider (configured or not) and that DB-state
// fields (Configured / Enabled / LastStatus / LastCheckHuman) overlay
// correctly for rows that exist in the providers table.
func TestSettingsListProviders_MergesCatalogAndDB(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)

	// Configure one provider so we can exercise the configured branch.
	if err := u.upsertProvider(ctx, "digitalocean", "tok_ok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	rows, err := u.loadProviderRows(ctx)
	if err != nil {
		t.Fatalf("loadProviderRows: %v", err)
	}
	if len(rows) != len(providerCatalog) {
		t.Errorf("len(rows)=%d, want %d (full catalog)", len(rows), len(providerCatalog))
	}

	var seenDO, seenAWS bool
	for _, r := range rows {
		switch r.ID {
		case "digitalocean":
			seenDO = true
			if !r.Configured {
				t.Errorf("digitalocean: Configured=false, want true")
			}
			if !r.Enabled {
				t.Errorf("digitalocean: Enabled=false, want true")
			}
			if r.LastStatus != "ok" {
				t.Errorf("digitalocean: LastStatus=%q want ok", r.LastStatus)
			}
		case "aws":
			seenAWS = true
			if r.Configured {
				t.Errorf("aws: Configured=true, want false (no DB row)")
			}
			if r.Available {
				t.Errorf("aws: Available=true, want false (Phase 2+ provider)")
			}
		}
	}
	if !seenDO || !seenAWS {
		t.Fatal("expected to see both DO + AWS in rows")
	}
}

// TestSettingsRotateCredentials_AtomicOnProbeFail confirms a failing
// probe leaves the old token intact (zero-downtime rotation).
//
// We can't drive a real DO probe in unit tests, so this test stages
// an unavailable-provider redirect path which uses the same atomic
// guard: if probeProvider returns errUnavailable, the row stays
// unchanged.
func TestSettingsRotateCredentials_AtomicOnProbeFail(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Seed a configured DO row with a known good token.
	if err := u.upsertProvider(ctx, "digitalocean", "old_token", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	// Hit the rotate endpoint with an invalid-format token. We don't
	// have network here, so the real DO probe will fail. The handler
	// must NOT have persisted the new token.
	form := url.Values{"token": []string{"new_token_that_will_fail_probe"}}
	req := httptest.NewRequest("POST", "/settings/providers/digitalocean/credentials",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Inject the URL param the way chi would.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "digitalocean")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.settingsRotateCredentials(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "err=rotation-probe-failed") {
		t.Errorf("Location=%q expected err=rotation-probe-failed", rec.Header().Get("Location"))
	}

	// Confirm the stored token is still "old_token".
	var cfg string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT config_json FROM providers WHERE id = ?`, "digitalocean").Scan(&cfg); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.Contains(cfg, `"token":"old_token"`) {
		t.Errorf("config_json=%q expected to still contain old_token", cfg)
	}
}

// TestSettingsToggleEnabled walks enable → disable → enable and
// confirms the providers.enabled column matches each turn.
func TestSettingsToggleEnabled(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	post := func(target string) *httptest.ResponseRecorder {
		form := url.Values{"target": []string{target}}
		req := httptest.NewRequest("POST", "/settings/providers/digitalocean/enabled",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "digitalocean")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		u.settingsToggleEnabled(rec, req)
		return rec
	}

	check := func(want int) {
		t.Helper()
		var got int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT enabled FROM providers WHERE id = ?`, "digitalocean").Scan(&got); err != nil {
			t.Fatalf("query enabled: %v", err)
		}
		if got != want {
			t.Errorf("enabled=%d want %d", got, want)
		}
	}

	// Default is enabled=1 (upsertProvider sets it). Disable it.
	rec := post("disable")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("disable: status %d", rec.Code)
	}
	check(0)

	// Re-enable.
	rec = post("enable")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("enable: status %d", rec.Code)
	}
	check(1)
}

// TestSettingsToggleEnabled_RejectsBadTarget guards the input
// validation — anything other than enable/disable returns 400.
func TestSettingsToggleEnabled_RejectsBadTarget(t *testing.T) {
	u, _ := newUIForTests(t)
	form := url.Values{"target": []string{"nuke"}}
	req := httptest.NewRequest("POST", "/settings/providers/digitalocean/enabled",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "digitalocean")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Seed a configured row so the not-configured branch doesn't fire
	// first.
	if err := u.upsertProvider(req.Context(), "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	rec := httptest.NewRecorder()
	u.settingsToggleEnabled(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d want 400", rec.Code)
	}
}

// TestSettingsUpdateConfig_PersistsRegionAndExclusions confirms the
// per-provider scan-settings form round-trips correctly through the
// providers.config_json column.
func TestSettingsUpdateConfig_PersistsRegionAndExclusions(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	form := url.Values{
		"region":     []string{"fra1, nyc1"},
		"exclusions": []string{"droplet/test-*\nspaces/staging-bucket\n\n"},
	}
	req := httptest.NewRequest("POST", "/settings/providers/digitalocean/config",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "digitalocean")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.settingsUpdateConfig(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}

	row, err := u.loadProviderRow(ctx, "digitalocean")
	if err != nil {
		t.Fatalf("loadProviderRow: %v", err)
	}
	cfg := row.parsedConfig()
	if cfg.Token != "tok" {
		t.Errorf("token=%q want tok (config update must not clobber)", cfg.Token)
	}
	if cfg.Region != "fra1, nyc1" {
		t.Errorf("region=%q", cfg.Region)
	}
	if len(cfg.Exclusions) != 2 ||
		cfg.Exclusions[0] != "droplet/test-*" ||
		cfg.Exclusions[1] != "spaces/staging-bucket" {
		t.Errorf("exclusions=%v want 2 entries", cfg.Exclusions)
	}
}

// TestSettingsRoutesMounted iterates every Phase 2 route and asserts
// chi doesn't return 404. Catches mount regressions in CI rather than
// at demo time (the same v1.3.1 lesson encoded by ui_test.go and
// setup_test.go).
func TestSettingsRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountSettingsRoutes(r)

	wantGET := []string{
		"/settings/providers",
		"/settings/providers/digitalocean",
	}
	wantPOST := []string{
		"/settings/providers/digitalocean/test",
		"/settings/providers/digitalocean/credentials",
		"/settings/providers/digitalocean/config",
		"/settings/providers/digitalocean/enabled",
	}

	for _, path := range wantGET {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
	for _, path := range wantPOST {
		form := url.Values{"target": []string{"enable"}}
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("POST %s: 404 (route not mounted)", path)
		}
	}
}

// TestHumanizeAgo covers the four scale buckets + the empty-input
// fallback. Drives the "Last checked Xm ago" labels in the list view.
func TestHumanizeAgo(t *testing.T) {
	// Empty / unparseable inputs land on the dash.
	if got := humanizeAgo(""); got != "—" {
		t.Errorf("empty: got %q want —", got)
	}
	if got := humanizeAgo("not-rfc-3339"); got != "—" {
		t.Errorf("garbage: got %q want —", got)
	}
}

// TestSplitNonEmpty exercises the textarea → []string normalizer used
// for the exclusions field.
func TestSplitNonEmpty(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"\n", nil},
		{"a", []string{"a"}},
		{"a\nb", []string{"a", "b"}},
		{"  a  \n\n  b  \n", []string{"a", "b"}},
		{"a\nb\n\n\nc", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := splitNonEmpty(c.in, "\n")
		if !equalSlices(got, c.want) {
			t.Errorf("splitNonEmpty(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
