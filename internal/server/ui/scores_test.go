package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// TestScoresView_RendersWithCompletedScans seeds completed scans
// with varied scores, hits the handler, and confirms a polyline
// + per-point circles render.
func TestScoresView_RendersWithCompletedScans(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)

	// Seed three completed scans across the last 14 days.
	for i, score := range []int{72, 78, 85} {
		ts := time.Now().Add(-time.Duration(14-i*7) * 24 * time.Hour).UTC().Format(time.RFC3339)
		_, _ = u.store.DB().ExecContext(ctx,
			`INSERT INTO scans (id, created_at, source, status, providers_scanned,
			                    frameworks_scanned, score, coverage, total_findings,
			                    actionable_findings)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"score-test-"+ts, ts, "daemon", "completed",
			`["digitalocean"]`, `["soc2"]`,
			score, 95, 50-score/2, 50-score/2)
	}

	req := httptest.NewRequest("GET", "/scores", nil)
	rec := httptest.NewRecorder()
	u.scoresView(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !contains2(body, "<polyline") {
		t.Errorf("body missing <polyline> element")
	}
	if !contains2(body, "<circle") {
		t.Errorf("body missing <circle> data points")
	}
}

// TestScoresView_EmptyState renders an empty-state when there are
// no completed scans.
func TestScoresView_EmptyState(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/scores", nil)
	rec := httptest.NewRecorder()
	u.scoresView(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !contains2(rec.Body.String(), "No completed scans yet") {
		t.Errorf("empty state copy missing")
	}
}

// TestScoresRoutesMounted: mount regression guard.
func TestScoresRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountScoresRoutes(r)
	req := httptest.NewRequest("GET", "/scores", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /scores: 404 (route not mounted)")
	}
}

// contains2 is a tiny helper avoiding importing strings just for
// Contains in the test file (strings is used elsewhere; keeping
// this file dependency-light).
func contains2(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
