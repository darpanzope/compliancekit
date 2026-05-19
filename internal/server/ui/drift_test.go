package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestDriftTimelinePartial_RendersForKnownFinding seeds a finding,
// hits the timeline endpoint, and confirms a chrome-less partial
// comes back referencing the scan.
func TestDriftTimelinePartial_RendersForKnownFinding(t *testing.T) {
	u, _ := newUIForTests(t)
	seedFindings(t, u, 5)
	var id string
	if err := u.store.DB().QueryRowContext(context.Background(),
		`SELECT id FROM findings LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query id: %v", err)
	}

	req := httptest.NewRequest("GET", "/findings/"+id+"/timeline", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.driftTimelinePartial(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("partial leaked <html> — expected chrome-less")
	}
	if !strings.Contains(body, "Lifecycle") {
		t.Errorf("body missing Lifecycle header")
	}
}

// TestDriftTimelinePartial_404 returns 404 for unknown id.
func TestDriftTimelinePartial_404(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/findings/nope/timeline", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nope")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.driftTimelinePartial(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d want 404", rec.Code)
	}
}
