package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// TestUpsertCheckOverride_RoundTripsAndUpdates confirms a fresh row
// lands in checks_state and that a second call updates rather than
// inserts a duplicate (the ON CONFLICT DO UPDATE clause).
func TestUpsertCheckOverride_RoundTripsAndUpdates(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	if err := u.upsertCheckOverride(ctx, "do-spaces-public-acl", false); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	var enabled int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT enabled FROM checks_state WHERE check_id = ?`,
		"do-spaces-public-acl").Scan(&enabled); err != nil {
		t.Fatalf("query: %v", err)
	}
	if enabled != 0 {
		t.Errorf("first upsert: enabled=%d want 0", enabled)
	}

	// Re-enable; same id should update in place.
	if err := u.upsertCheckOverride(ctx, "do-spaces-public-acl", true); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT enabled FROM checks_state WHERE check_id = ?`,
		"do-spaces-public-acl").Scan(&enabled); err != nil {
		t.Fatalf("query: %v", err)
	}
	if enabled != 1 {
		t.Errorf("second upsert: enabled=%d want 1", enabled)
	}

	// Confirm only one row exists for this id.
	var rowCount int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM checks_state WHERE check_id = ?`,
		"do-spaces-public-acl").Scan(&rowCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("rowCount=%d want 1 (ON CONFLICT must update, not insert duplicate)", rowCount)
	}
}

// TestRowMatchesFilters covers the search + chip filter logic — query
// substring match (case-insensitive), severity OR-set, provider
// AND-across, framework intersection.
func TestRowMatchesFilters(t *testing.T) {
	row := checkRow{
		ID:         "do-spaces-public-acl",
		Severity:   "high",
		Provider:   "digitalocean",
		Service:    "spaces",
		Title:      "Spaces bucket public ACL",
		Frameworks: []string{"soc2", "cis-do"},
	}

	cases := []struct {
		name string
		q    string
		sev  []string
		pro  []string
		fw   []string
		want bool
	}{
		{"empty filters → match", "", nil, nil, nil, true},
		{"q matches id substring (case-insensitive)", "PUBLIC", nil, nil, nil, true},
		{"q matches title substring", "bucket public", nil, nil, nil, true},
		{"q misses → reject", "vpc", nil, nil, nil, false},
		{"sev matches → ok", "", []string{"high", "critical"}, nil, nil, true},
		{"sev misses → reject", "", []string{"low"}, nil, nil, false},
		{"provider matches → ok", "", nil, []string{"digitalocean"}, nil, true},
		{"provider misses → reject", "", nil, []string{"aws"}, nil, false},
		{"framework matches one → ok", "", nil, nil, []string{"cis-do"}, true},
		{"framework matches none → reject", "", nil, nil, []string{"pci-dss"}, false},
		{"multiple filters AND across", "spaces", []string{"high"}, []string{"digitalocean"}, []string{"soc2"}, true},
	}
	for _, c := range cases {
		got := rowMatchesFilters(row, c.q, c.sev, c.pro, c.fw)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestSplitCSV covers the comma-separated filter param normalizer.
func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := splitCSV(c.in)
		if !equalSlices(got, c.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestChecksToggle_WritesOverride exercises the POST handler — a
// real check id gets a row in checks_state with the inverted flag.
func TestChecksToggle_WritesOverride(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)

	// Pick a real registered check id so the not-found branch
	// doesn't fire.
	registered := compliancekit.RegisteredChecks()
	if len(registered) == 0 {
		t.Skip("no checks registered in this build")
	}
	id := registered[0].ID

	req := httptest.NewRequest("POST", "/checks/"+id+"/toggle", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.checksToggle(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d want 303", rec.Code)
	}

	var enabled int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT enabled FROM checks_state WHERE check_id = ?`, id).Scan(&enabled); err != nil {
		t.Fatalf("query: %v", err)
	}
	if enabled != 0 {
		t.Errorf("expected toggle-off (enabled=0), got enabled=%d", enabled)
	}
}

// TestChecksToggle_UnknownID returns 404 not 500.
func TestChecksToggle_UnknownID(t *testing.T) {
	u, _ := newUIForTests(t)
	req := httptest.NewRequest("POST", "/checks/does-not-exist/toggle", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "does-not-exist")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	u.checksToggle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d want 404", rec.Code)
	}
}

// TestChecksRoutesMounted iterates the Phase 3 routes — mount
// regression guard.
func TestChecksRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountChecksRoutes(r)

	for _, path := range []string{"/checks", "/checks/diff"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}

	registered := compliancekit.RegisteredChecks()
	if len(registered) == 0 {
		return
	}
	id := registered[0].ID
	req := httptest.NewRequest("POST", "/checks/"+id+"/toggle", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("POST /checks/{id}/toggle: 404 (route not mounted)")
	}
}

// TestChecksList_FiltersApplied confirms the integration glue —
// query params actually narrow the rendered Items.
func TestChecksList_FiltersApplied(t *testing.T) {
	u, _ := newUIForTests(t)

	// Bare GET /checks — should return some checks.
	req := httptest.NewRequest("GET", "/checks", nil)
	rec := httptest.NewRecorder()
	u.checksList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bare /checks: status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "matching of") {
		t.Errorf("bare /checks body missing header text")
	}

	// Provider filter to a known-empty namespace narrows results.
	req = httptest.NewRequest("GET", "/checks?provider=banana-cloud", nil)
	rec = httptest.NewRecorder()
	u.checksList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered /checks: status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No checks match the current filters") {
		t.Errorf("filtered /checks expected empty-state message")
	}
}
