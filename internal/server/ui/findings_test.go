package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// seedFindings inserts n synthetic findings spread across two scans
// + two providers for the explorer tests.
func seedFindings(t *testing.T, u *UI, n int) {
	t.Helper()
	ctx := context.Background()
	// Need two scan rows for the FK.
	scanA, _ := u.enqueueWizardScanMulti(ctx, []string{"digitalocean"})
	scanB, _ := u.enqueueWizardScanMulti(ctx, []string{"aws"})
	now := time.Now().UTC().Format(time.RFC3339)
	sevs := []string{"critical", "high", "medium", "low", "info"}
	provs := []string{"digitalocean", "aws"}
	q := `INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status,
	                             provider, resource_id, resource_name, resource_type,
	                             message, framework_ids, first_seen_at, last_seen_at, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for i := 0; i < n; i++ {
		scan := scanA
		if i%2 == 0 {
			scan = scanB
		}
		sev := sevs[i%len(sevs)]
		prov := provs[i%len(provs)]
		_, err := u.store.DB().ExecContext(ctx, q,
			uuid.NewString(), scan, "fp-"+string(rune('a'+i%26)),
			"chk-"+string(rune('a'+i%26)), sev, "fail", prov,
			"res-id-"+string(rune('a'+i%26)),
			"resource-"+string(rune('a'+i%26)),
			"resource_type_x", "msg", `["soc2","cis-do"]`,
			now, now, now)
		if err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
}

// TestFindingsList_Pagination seeds 75 findings and confirms the
// initial page returns 50 + a next-cursor.
func TestFindingsList_Pagination(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 75)

	items, next, err := u.queryFindings(ctx, findingFilters{PerPage: 50})
	if err != nil {
		t.Fatalf("queryFindings: %v", err)
	}
	if len(items) != 50 {
		t.Errorf("len(items)=%d want 50", len(items))
	}
	if next == "" {
		t.Errorf("expected non-empty cursor when more rows remain")
	}

	// Follow the cursor — should get the remaining 25.
	items2, next2, err := u.queryFindings(ctx, findingFilters{PerPage: 50, Cursor: next})
	if err != nil {
		t.Fatalf("queryFindings page 2: %v", err)
	}
	if len(items2) != 25 {
		t.Errorf("page 2: len=%d want 25", len(items2))
	}
	if next2 != "" {
		t.Errorf("page 2: expected empty cursor (end of results), got %q", next2)
	}
}

// TestFindingsList_SeverityFilter narrows by severity.
func TestFindingsList_SeverityFilter(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 20)

	items, _, err := u.queryFindings(ctx, findingFilters{
		Severities: []string{"critical", "high"},
		PerPage:    50,
	})
	if err != nil {
		t.Fatalf("queryFindings: %v", err)
	}
	for _, it := range items {
		if it.Severity != "critical" && it.Severity != "high" {
			t.Errorf("got severity %q outside filter set", it.Severity)
		}
	}
}

// TestFindingsList_ProviderFilter narrows by provider.
func TestFindingsList_ProviderFilter(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 20)

	items, _, err := u.queryFindings(ctx, findingFilters{
		Providers: []string{"digitalocean"},
		PerPage:   50,
	})
	if err != nil {
		t.Fatalf("queryFindings: %v", err)
	}
	for _, it := range items {
		if it.Provider != "digitalocean" {
			t.Errorf("got provider %q outside filter set", it.Provider)
		}
	}
}

// TestFindingsList_NameSearch matches against resource_name + check_id.
func TestFindingsList_NameSearch(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 26) // one per a–z so we know exact matches

	items, _, err := u.queryFindings(ctx, findingFilters{
		NameQuery: "resource-a",
		PerPage:   50,
	})
	if err != nil {
		t.Fatalf("queryFindings: %v", err)
	}
	if len(items) == 0 {
		t.Errorf("name-search returned 0 rows; expected at least 1")
	}
}

// TestCountFindingsBySeverity returns the histogram.
func TestCountFindingsBySeverity(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	seedFindings(t, u, 25) // 5 of each severity

	stats, err := u.countFindingsBySeverity(ctx, findingFilters{})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if stats.Total != 25 {
		t.Errorf("total=%d want 25", stats.Total)
	}
	if stats.Critical != 5 || stats.High != 5 || stats.Medium != 5 || stats.Low != 5 || stats.Info != 5 {
		t.Errorf("severity buckets off: %+v", stats)
	}
}

// TestCursorRoundTrip confirms encode/decode are inverses.
func TestCursorRoundTrip(t *testing.T) {
	in := cursorPos{createdAt: "2026-05-19T00:00:00Z", id: "abc-123", valid: true}
	out := decodeCursor(encodeCursor(in))
	if !out.valid {
		t.Fatal("expected valid cursor after round-trip")
	}
	if out.createdAt != in.createdAt || out.id != in.id {
		t.Errorf("round-trip mismatch: %+v vs %+v", out, in)
	}

	// Empty input → invalid (no panic).
	if decodeCursor("").valid {
		t.Error("empty cursor should be invalid")
	}
	// Garbage input → invalid.
	if decodeCursor("not-base64-at-all").valid {
		t.Error("garbage cursor should be invalid")
	}
}

// TestFindingsRoutesMounted: mount regression guard.
func TestFindingsRoutesMounted(t *testing.T) {
	u, _ := newUIForTests(t)
	r := chi.NewRouter()
	u.mountFindingsRoutes(r)

	for _, path := range []string{"/findings", "/findings/rows"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("GET %s: 404 (route not mounted)", path)
		}
	}
}

// TestParseFindingFilters covers the URL query parser — repeated
// keys + comma-separated values both collect into the slice.
func TestParseFindingFilters(t *testing.T) {
	cases := []struct {
		name  string
		input map[string][]string
		check func(f findingFilters) bool
	}{
		{
			"repeated keys",
			map[string][]string{"severity": {"critical", "high"}},
			func(f findingFilters) bool {
				return len(f.Severities) == 2 && f.Severities[0] == "critical" && f.Severities[1] == "high"
			},
		},
		{
			"comma-separated",
			map[string][]string{"severity": {"critical,high"}},
			func(f findingFilters) bool { return len(f.Severities) == 2 },
		},
		{
			"per_page default",
			map[string][]string{},
			func(f findingFilters) bool { return f.PerPage == 50 },
		},
		{
			"per_page clamped",
			map[string][]string{"per_page": {"5000"}},
			func(f findingFilters) bool { return f.PerPage == 50 }, // > 200 → default
		},
	}
	for _, c := range cases {
		f := parseFindingFilters(c.input)
		if !c.check(f) {
			t.Errorf("%s: unexpected filters %+v", c.name, f)
		}
	}
	_ = strings.Builder{}
}
