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

// TestProviderServicesFromRegistry confirms the derived service list
// is non-empty for at least one known-shipping provider (DO covers
// the v0.9 / v0.19 depth pass), and is sorted alphabetically.
func TestProviderServicesFromRegistry(t *testing.T) {
	doSvcs := providerServicesFromRegistry("digitalocean")
	if len(doSvcs) == 0 {
		t.Skip("no DO checks registered in this build — registry empty")
	}
	// Sorted invariant.
	for i := 1; i < len(doSvcs); i++ {
		if doSvcs[i-1] > doSvcs[i] {
			t.Errorf("DO services not sorted at index %d: %q > %q",
				i, doSvcs[i-1], doSvcs[i])
		}
	}
	// Unknown provider → empty roster (no panic).
	got := providerServicesFromRegistry("not-a-provider")
	if len(got) != 0 {
		t.Errorf("unknown provider: got %d entries, want 0", len(got))
	}
}

// TestSettingsUpdateServices_FiltersBogusServices guards against
// posted service names that aren't in the registry — they shouldn't
// land in config_json.
func TestSettingsUpdateServices_FiltersBogusServices(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	doSvcs := providerServicesFromRegistry("digitalocean")
	if len(doSvcs) < 2 {
		t.Skip("need at least 2 DO services to exercise the filter")
	}

	form := url.Values{}
	// One real service + one bogus.
	form.Add("service", doSvcs[0])
	form.Add("service", "made-up-service-xyz")
	req := httptest.NewRequest("POST", "/settings/providers/digitalocean/services",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "digitalocean")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.settingsUpdateServices(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}

	row, err := u.loadProviderRow(ctx, "digitalocean")
	if err != nil {
		t.Fatalf("loadProviderRow: %v", err)
	}
	cfg := row.parsedConfig()
	if len(cfg.Services) != 1 || cfg.Services[0] != doSvcs[0] {
		t.Errorf("services=%v want [%q] (bogus entry must be dropped)", cfg.Services, doSvcs[0])
	}
}

// TestSettingsUpdateServices_AllPickedStoresNil confirms the
// "everything picked = no allow-list" sentinel — keeps the YAML
// preview clean and matches the unconfigured default semantics.
func TestSettingsUpdateServices_AllPickedStoresNil(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	if err := u.upsertProvider(ctx, "digitalocean", "tok", nil); err != nil {
		t.Fatalf("upsertProvider: %v", err)
	}

	doSvcs := providerServicesFromRegistry("digitalocean")
	if len(doSvcs) == 0 {
		t.Skip("no DO services to exercise the all-picked path")
	}

	form := url.Values{}
	for _, s := range doSvcs {
		form.Add("service", s)
	}
	req := httptest.NewRequest("POST", "/settings/providers/digitalocean/services",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "digitalocean")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.settingsUpdateServices(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}

	row, err := u.loadProviderRow(ctx, "digitalocean")
	if err != nil {
		t.Fatalf("loadProviderRow: %v", err)
	}
	cfg := row.parsedConfig()
	if cfg.Services != nil {
		t.Errorf("services=%v want nil (all-picked sentinel)", cfg.Services)
	}
}
