package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestLoadResourceMap_GroupsByProviderService confirms findings
// group correctly into the provider → service → resource tree with
// rolled-up severity counts.
func TestLoadResourceMap_GroupsByProviderService(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 10)

	providers, total, err := u.loadResourceMap(ctx)
	if err != nil {
		t.Fatalf("loadResourceMap: %v", err)
	}
	if total == 0 {
		t.Fatal("expected non-zero resource count")
	}
	if len(providers) == 0 {
		t.Fatal("expected non-empty provider list")
	}
	for _, p := range providers {
		// Each provider rolls up severity counts from its resources.
		var rolled int
		for _, s := range p.Services {
			for _, r := range s.Resources {
				rolled += r.Critical + r.High + r.Medium + r.Low
			}
		}
		ptot := p.Critical + p.High + p.Medium + p.Low
		if ptot != rolled {
			t.Errorf("provider %q rolled-up count %d != sum of resource counts %d",
				p.Provider, ptot, rolled)
		}
	}
}

// TestResourceMapRoutesMounted: mount regression guard.
func TestResourceMapRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountResourceMapRoutes(r)
	req := httptest.NewRequest("GET", "/resources/map", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /resources/map: 404 (route not mounted)")
	}
}
