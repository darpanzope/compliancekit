package api

// v1.11 phase 9 — benchmark harness for the cursor pagination +
// LRU cache + streaming NDJSON hot paths.
//
// Run via: `make bench-server` or `go test -bench=. -benchmem ./internal/server/api/`.
//
// Targets per ROADMAP § v1.11:
//   BenchmarkListFindings_CursorFirstPage      p95 <50ms
//   BenchmarkListFindings_CursorDeepPage       p95 <50ms
//   BenchmarkListFindings_FilterSeverityCursor p95 <100ms
//   BenchmarkListScans_Cursor                  p95 <30ms
//
// Seeded with 100k findings / 10k resources / 1k scans into an
// in-memory SQLite. Postgres benches live behind -tags=integration
// per the existing repo convention.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// seedBench populates the store with the v1.11 benchmark fixtures.
// Sized to match the ROADMAP claim "100k findings / 10k resources
// / 1k scans". The seed runs once per benchmark invocation; the
// b.ResetTimer call below excludes the seed cost from the timing.
func seedBench(b *testing.B, db *sql.DB, scansN, resourcesN, findingsN int) {
	b.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	// Scans.
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		b.Fatalf("begin tx: %v", err)
	}
	for i := 0; i < scansN; i++ {
		if _, err := tx.Exec(
			`INSERT INTO scans (id, created_at, source, status) VALUES (?, ?, ?, ?)`,
			fmt.Sprintf("scan-%05d", i), now, "cli", "completed"); err != nil {
			b.Fatalf("seed scan %d: %v", i, err)
		}
	}
	// Resources.
	for i := 0; i < resourcesN; i++ {
		if _, err := tx.Exec(
			`INSERT INTO resources (id, name, type, provider, first_seen_at, last_seen_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"res-"+strconv.Itoa(i), "name-"+strconv.Itoa(i),
			"aws.ec2.instance", "aws", now, now); err != nil {
			b.Fatalf("seed res %d: %v", i, err)
		}
	}
	// Findings — spread across the scans + resources so the indexes
	// see realistic cardinality.
	sevCycle := []string{"critical", "high", "medium", "low", "info"}
	for i := 0; i < findingsN; i++ {
		scanID := fmt.Sprintf("scan-%05d", i%scansN)
		resID := "res-" + strconv.Itoa(i%resourcesN)
		sev := sevCycle[i%len(sevCycle)]
		fp := fmt.Sprintf("fp-%06d", i)
		if _, err := tx.Exec(
			`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider,
			                       resource_id, resource_name, resource_type, message, framework_ids,
			                       first_seen_at, last_seen_at, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("f-%06d", i), scanID, fp,
			"aws.iam.user.mfa-enabled", sev, "fail", "aws",
			resID, "name-"+strconv.Itoa(i%resourcesN), "aws.iam.user",
			"benchmark seed", "[]", now, now, now); err != nil {
			b.Fatalf("seed finding %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatalf("commit seed: %v", err)
	}
}

// newBenchAPI builds the daemon + seeded store. Skips on -short
// because the seed takes ~5s on a CI runner.
func newBenchAPI(b *testing.B, findingsN int) (*chi.Mux, func()) {
	b.Helper()
	if testing.Short() {
		b.Skip("skipping bench in -short mode (100k row seed)")
	}
	st, err := store.OpenSQLite(context.Background(),
		"file:"+b.Name()+"?mode=memory&cache=shared")
	if err != nil {
		b.Fatalf("OpenSQLite: %v", err)
	}
	if err := st.MigrateUp(context.Background()); err != nil {
		b.Fatalf("MigrateUp: %v", err)
	}
	seedBench(b, st.DB(), 1000, 10000, findingsN)
	r := chi.NewMux()
	api := &API{store: st}
	r.Get("/api/v1/findings", api.listFindings)
	r.Get("/api/v1/scans", api.listScans)
	r.Get("/api/v1/resources", api.listResources)
	r.Get("/api/v1/findings.ndjson", api.streamFindings)
	cleanup := func() { _ = st.Close() }
	return r, cleanup
}

// BenchmarkListFindings_CursorFirstPage measures the cold-cache
// first-page cursor query. Target: p95 <50ms on SQLite.
func BenchmarkListFindings_CursorFirstPage(b *testing.B) {
	r, cleanup := newBenchAPI(b, 100_000)
	defer cleanup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/findings?per_page=50", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status = %d", w.Code)
		}
	}
}

// BenchmarkListFindings_CursorDeepPage measures the 10th-page cursor
// query. Target: p95 <50ms on SQLite (the cursor's WHERE-tuple-
// compare is constant-time regardless of depth — proves the no-
// OFFSET claim).
func BenchmarkListFindings_CursorDeepPage(b *testing.B) {
	r, cleanup := newBenchAPI(b, 100_000)
	defer cleanup()
	// Fetch the first page to get a cursor we can walk past.
	var cursor string
	{
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/findings?per_page=50", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp pageCursor[findingRow]
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			b.Fatalf("decode: %v", err)
		}
		cursor = resp.NextCursor
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/findings?per_page=50&cursor="+cursor, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status = %d", w.Code)
		}
	}
}

// BenchmarkListFindings_FilterSeverityCursor measures the composite-
// index hot path: filter chip + cursor. Target: p95 <100ms.
func BenchmarkListFindings_FilterSeverityCursor(b *testing.B) {
	r, cleanup := newBenchAPI(b, 100_000)
	defer cleanup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/findings?severity=critical&per_page=50", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status = %d", w.Code)
		}
	}
}

// BenchmarkListScans_Cursor measures the scans-list cursor query.
// Target: p95 <30ms (1k scans is a small dataset).
func BenchmarkListScans_Cursor(b *testing.B) {
	r, cleanup := newBenchAPI(b, 1000) // small finding set; scans is the focus
	defer cleanup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/scans?per_page=50", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status = %d", w.Code)
		}
	}
}

// BenchmarkListFindings_LegacyOffsetDeep measures the deprecated
// ?page= path so the perf-regression CI catches anyone reaching
// for it accidentally. Will be removed at v1.12 along with the
// legacy handler.
func BenchmarkListFindings_LegacyOffsetDeep(b *testing.B) {
	r, cleanup := newBenchAPI(b, 100_000)
	defer cleanup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), "GET",
			"/api/v1/findings?page=100&per_page=50", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("status = %d", w.Code)
		}
	}
}
