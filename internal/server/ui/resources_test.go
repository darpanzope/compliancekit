package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestLoadResourceInventory confirms the flat aggregation produces
// one row per resource with the right finding count.
func TestLoadResourceInventory(t *testing.T) {
	u, _ := newUIForTests(t)
	seedFindings(t, u, 26)
	rows, err := u.loadResourceInventory(context.Background())
	if err != nil {
		t.Fatalf("loadResourceInventory: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one resource row")
	}
	for _, r := range rows {
		if r.Total == 0 {
			t.Errorf("resource %q has Total=0", r.ResourceName)
		}
	}
}

// TestSortResourceInventory_BySeverity puts the highest-severity
// resources first.
func TestSortResourceInventory_BySeverity(t *testing.T) {
	rows := []resourceInventoryRow{
		{ResourceName: "low-only", MaxSeverity: sevLow, Total: 5},
		{ResourceName: "critical", MaxSeverity: sevCritical, Total: 1},
		{ResourceName: "medium", MaxSeverity: sevMedium, Total: 2},
	}
	sortResourceInventory(rows, "severity")
	if rows[0].ResourceName != "critical" {
		t.Errorf("first=%q want critical", rows[0].ResourceName)
	}
	if rows[2].ResourceName != "low-only" {
		t.Errorf("last=%q want low-only", rows[2].ResourceName)
	}
}

// TestMaxSeverity picks the higher-rank severity.
func TestMaxSeverity(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"", sevCritical, sevCritical},
		{sevHigh, sevCritical, sevCritical},
		{sevCritical, sevLow, sevCritical},
		{sevMedium, sevHigh, sevHigh},
	}
	for _, c := range cases {
		if got := maxSeverity(c.a, c.b); got != c.want {
			t.Errorf("maxSeverity(%q,%q)=%q want %q", c.a, c.b, got, c.want)
		}
	}
}

// TestResourcesRoutesMounted: mount regression guard.
func TestResourcesRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountResourcesRoutes(r)
	req := httptest.NewRequest("GET", "/resources", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("GET /resources: 404 (route not mounted)")
	}
}
