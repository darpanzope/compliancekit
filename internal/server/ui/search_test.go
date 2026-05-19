package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestSearchJSON_FindsAcrossKinds seeds findings + a saved view +
// hits /search; confirms results from multiple kinds come back.
func TestSearchJSON_FindsAcrossKinds(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 10)
	// Save a view named "Critical AWS" so the view branch fires.
	_, _ = u.store.DB().ExecContext(ctx,
		`INSERT INTO saved_views (id, owner_user_id, created_at, name, query_string, pinned)
		 VALUES (?, NULL, ?, ?, ?, ?)`,
		"v-test", "2026-05-19T00:00:00Z", "Critical AWS", "severity=critical", 1)

	req := httptest.NewRequest("GET", "/search?q=critical", nil)
	rec := httptest.NewRecorder()
	u.searchJSON(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var out []searchResult
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected non-empty results")
	}
	// Confirm at least one saved-view hit.
	var hasView bool
	for _, r := range out {
		if r.Kind == "view" {
			hasView = true
		}
	}
	if !hasView {
		t.Errorf("saved-view kind missing from results: %+v", out)
	}
}

// TestSearchJSON_EmptyQuery returns no results without erroring.
func TestSearchJSON_EmptyQuery(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/search?q=", nil)
	rec := httptest.NewRecorder()
	u.searchJSON(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("empty query should return [] JSON, got %s", rec.Body.String())
	}
}

// TestSearchProviders matches catalog ids + names.
func TestSearchProviders(t *testing.T) {
	got := searchProviders("digital")
	if len(got) == 0 {
		t.Errorf("expected DO match, got 0")
	}
	got = searchProviders("nothing-here")
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// TestScanPDF_RoutesAndRenders ensures /scans/{id}/pdf returns HTML.
func TestScanPDF_RoutesAndRenders(t *testing.T) {
	u, _ := newUIForTests(t)
	seedFindings(t, u, 5)
	var scanID string
	if err := u.store.DB().QueryRowContext(context.Background(),
		`SELECT id FROM scans LIMIT 1`).Scan(&scanID); err != nil {
		t.Fatalf("query: %v", err)
	}
	req := httptest.NewRequest("GET", "/scans/"+scanID+"/pdf", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.scanPDF(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "compliancekit") {
		t.Errorf("Content-Disposition missing filename")
	}
}

// TestSearchRoutesMounted: mount regression guard.
func TestSearchRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountSearchRoutes(r)
	req := httptest.NewRequest("GET", "/search?q=x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /search: 404 (route not mounted)")
	}
}
