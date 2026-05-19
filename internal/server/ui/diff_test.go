package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TestDiffScans_NewResolvedChanged seeds two scans with overlapping
// + diverging findings and confirms the three sections shake out.
func TestDiffScans_NewResolvedChanged(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	scanA, _ := u.enqueueWizardScanMulti(ctx, []string{"digitalocean"})
	scanB, _ := u.enqueueWizardScanMulti(ctx, []string{"digitalocean"})

	insert := func(scan, fp, status string) {
		_, err := st.DB().ExecContext(ctx,
			`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status,
			                       provider, resource_id, resource_name, resource_type,
			                       message, framework_ids, first_seen_at, last_seen_at, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.NewString(), scan, fp, "do-check-x", "high", status,
			"digitalocean", "res-1", "resource-1", "droplet",
			"msg", `["soc2"]`, "2026-05-19T00:00:00Z", "2026-05-19T00:00:00Z", "2026-05-19T00:00:00Z")
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// fp-shared: present in both, status changes
	insert(scanA, "fp-shared", "fail")
	insert(scanB, "fp-shared", "pass")
	// fp-only-a: in A only → resolved
	insert(scanA, "fp-only-a", "fail")
	// fp-only-b: in B only → new
	insert(scanB, "fp-only-b", "fail")

	res, err := u.diffScans(ctx, scanA, scanB)
	if err != nil {
		t.Fatalf("diffScans: %v", err)
	}
	if len(res.New) != 1 || res.New[0].FindingID == "" {
		t.Errorf("expected 1 new finding, got %+v", res.New)
	}
	if len(res.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(res.Resolved))
	}
	if len(res.Changed) != 1 {
		t.Errorf("expected 1 changed finding, got %d", len(res.Changed))
	}
}

// TestDiffRoutesMounted: mount regression guard.
func TestDiffRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountDiffRoutes(r)
	req := httptest.NewRequest("GET", "/scans/diff", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /scans/diff: 404 (route not mounted)")
	}
}
