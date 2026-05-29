package search

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func newTestIndex(t *testing.T) *Index {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "search.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// A scan + a couple of findings + a resource so the index has real
	// rows alongside the static settings/docs entries.
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO scans (id, created_at, source, status, providers_scanned, frameworks_scanned, score, coverage, total_findings, actionable_findings, duration_ms)
		 VALUES ('scan-aaa', ?, 'daemon', 'completed', '["aws"]', '["soc2"]', 80, 95, 2, 2, 1000)`, now)
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider, resource_id, resource_name, resource_type, message, framework_ids, first_seen_at, last_seen_at, created_at)
		 VALUES ('f1','scan-aaa','fp1','aws-ec2-public-ip','high','fail','aws','aws:ec2:web-01','web-01','ec2','EC2 instance has a public IP','["soc2"]',?,?,?)`, now, now, now)
	_, _ = st.DB().ExecContext(ctx,
		`INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at, last_seen_scan_id)
		 VALUES ('aws:ec2:web-01','web-01','ec2','aws',?,?,'scan-aaa')`, now, now)
	idx := New(st)
	if err := idx.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	return idx
}

func TestIndexRebuildPopulates(t *testing.T) {
	t.Parallel()
	idx := newTestIndex(t)
	// Static entries (settings + docs) + the 3 seeded rows.
	if idx.Size() < 12 {
		t.Errorf("index size = %d, want >= 12 (statics + seeded rows)", idx.Size())
	}
	if idx.BuiltAt().IsZero() {
		t.Error("BuiltAt should be set after Rebuild")
	}
}

func TestSearchFuzzyMatch(t *testing.T) {
	t.Parallel()
	idx := newTestIndex(t)
	resp := idx.Search("ec2", nil, 20, "")
	if len(resp.Results) == 0 {
		t.Fatal("search 'ec2' returned no results")
	}
	// The ec2 finding + resource should both surface.
	var sawFinding, sawResource bool
	for _, r := range resp.Results {
		switch r.Type {
		case compliancekit.SearchTypeFinding:
			sawFinding = true
		case compliancekit.SearchTypeResource:
			sawResource = true
		}
	}
	if !sawFinding || !sawResource {
		t.Errorf("expected ec2 finding + resource; finding=%v resource=%v", sawFinding, sawResource)
	}
}

func TestSearchTypeFilter(t *testing.T) {
	t.Parallel()
	idx := newTestIndex(t)
	resp := idx.Search("web", []compliancekit.SearchType{compliancekit.SearchTypeResource}, 20, "")
	for _, r := range resp.Results {
		if r.Type != compliancekit.SearchTypeResource {
			t.Errorf("type filter leaked a %q result", r.Type)
		}
	}
}

func TestSearchEmptyQueryReturnsSuggestions(t *testing.T) {
	t.Parallel()
	idx := newTestIndex(t)
	resp := idx.Search("", nil, 5, "")
	if len(resp.Results) == 0 {
		t.Error("empty query should return recency-ranked suggestions")
	}
}

func TestSearchCursorPagination(t *testing.T) {
	t.Parallel()
	idx := newTestIndex(t)
	first := idx.Search("settings", nil, 2, "")
	if first.NextCursor == "" {
		t.Skip("not enough 'settings' hits to paginate")
	}
	second := idx.Search("settings", nil, 2, first.NextCursor)
	if len(second.Results) == 0 {
		t.Error("second page should have results")
	}
	// No overlap between page 1 and page 2.
	seen := map[string]bool{}
	for _, r := range first.Results {
		seen[string(r.Type)+r.ID] = true
	}
	for _, r := range second.Results {
		if seen[string(r.Type)+r.ID] {
			t.Errorf("cursor paging returned a duplicate: %s/%s", r.Type, r.ID)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 20, 9999} {
		if got := decodeCursor(encodeCursor(n)); got != n {
			t.Errorf("cursor round-trip %d → %d", n, got)
		}
	}
	if decodeCursor("not-base64!!") != 0 {
		t.Error("malformed cursor should decode to 0")
	}
}
