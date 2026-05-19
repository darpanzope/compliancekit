package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestFindingDetailPartial_RendersPanel hits the partial endpoint
// and confirms the side-panel HTML comes back with the right shape
// (no daemon chrome; has the finding metadata).
func TestFindingDetailPartial_RendersPanel(t *testing.T) {
	u, _ := newUIForTests(t)
	seedFindings(t, u, 5)

	// Pull a known finding id.
	var id string
	if err := u.store.DB().QueryRowContext(context.Background(),
		`SELECT id FROM findings LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query id: %v", err)
	}

	req := httptest.NewRequest("GET", "/findings/"+id+"/detail", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.findingDetailPartial(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	// Partial doesn't render the daemon chrome (no <html>, no nav).
	if strings.Contains(body, "<html") {
		t.Errorf("partial leaked <html> — expected chrome-less output")
	}
	if !strings.Contains(body, "Overview") {
		t.Errorf("partial missing Overview tab label")
	}
	if !strings.Contains(body, "Resource") {
		t.Errorf("partial missing Resource section")
	}
}

// TestFindingDetailPartial_404 returns 404 for unknown id.
func TestFindingDetailPartial_404(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("GET", "/findings/does-not-exist/detail", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "does-not-exist")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.findingDetailPartial(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d want 404", rec.Code)
	}
}

// TestCountWaiversForResource matches both exact + wildcard waivers.
func TestCountWaiversForResource(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Exact-match waiver.
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"w1", "do-spaces-public-acl", "res-id-a", "reason", "approver", "2026-05-19T00:00:00Z")
	// Wildcard waiver.
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"w2", "do-spaces-public-acl", "*", "reason", "approver", "2026-05-19T00:00:00Z")

	total, active := u.countWaiversForResource(ctx, "do-spaces-public-acl", "res-id-a")
	if total != 2 {
		t.Errorf("total=%d want 2 (exact + wildcard)", total)
	}
	if !active {
		t.Errorf("expected anyActive=true (neither expired nor revoked)")
	}

	// Different resource → only wildcard matches.
	total2, _ := u.countWaiversForResource(ctx, "do-spaces-public-acl", "different-resource")
	if total2 != 1 {
		t.Errorf("different resource: total=%d want 1 (just wildcard)", total2)
	}
}
