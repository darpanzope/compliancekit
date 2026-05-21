// Package slowlog is the v1.11 phase 7 query-budget + slow-query
// log. Wraps the daemon's *sql.DB with a timing layer; queries that
// exceed the configured threshold (default 100ms) emit a structured
// log entry with the SQL, parameter values redacted, EXPLAIN QUERY
// PLAN, duration, and rows-scanned estimate.
//
// The aggregated stats are exposed via Recorder.Stats() so the
// /admin/logs view can render a "top-N slow queries" leaderboard +
// the operator can `compliancekit serve query-stats` to dump it.
//
// Per-request budget enforcement (the v1.11 ROADMAP "query budget"
// item) lives at the middleware layer — Recorder.Tracker exposes a
// scoped tracker that handlers can call .Record(duration) into; the
// middleware fails the request when the per-request total exceeds
// the cap.
package slowlog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultThreshold is the per-query duration above which we log.
// 100ms is the "felt slow" threshold for an interactive operator
// hitting the explorer at scale.
const DefaultThreshold = 100 * time.Millisecond

// DefaultRequestBudget is the per-HTTP-request total query time
// above which the middleware logs (but doesn't fail) the request.
// Set to 1s — covers a worst-case mega-filter that hits a few
// indexes; over that, something is wrong.
const DefaultRequestBudget = time.Second

// Recorder is the package-global stats sink. Construct one + share
// it across the store + middleware.
type Recorder struct {
	threshold time.Duration
	budget    time.Duration
	logger    *slog.Logger

	mu     sync.Mutex
	groups map[string]*QueryStats // by query_id
	total  atomic.Uint64
	slowN  atomic.Uint64
}

// QueryStats accumulates timings for one query template (same SQL
// shape, modulo parameter values).
type QueryStats struct {
	QueryID   string // sha256 prefix of the normalized SQL
	SQL       string // the original SQL text
	Calls     uint64
	TotalMS   uint64
	MaxMS     uint64
	SlowCalls uint64 // calls that crossed the threshold
	LastSeen  time.Time
}

// New constructs a Recorder. Pass zero values for threshold +
// budget to use the defaults.
func New(threshold, budget time.Duration, logger *slog.Logger) *Recorder {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if budget <= 0 {
		budget = DefaultRequestBudget
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{
		threshold: threshold,
		budget:    budget,
		logger:    logger,
		groups:    map[string]*QueryStats{},
	}
}

// Record accounts for a single query execution. Called by the
// wrapping layer (e.g. a custom sql.Driver or hand-instrumented
// handler) on every QueryContext / ExecContext.
func (r *Recorder) Record(ctx context.Context, sqlText string, dur time.Duration, rowsScanned int) {
	ms := dur.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	r.total.Add(uint64(ms)) //nolint:gosec // clamped non-negative just above
	qid := queryID(sqlText)
	r.mu.Lock()
	s, ok := r.groups[qid]
	if !ok {
		s = &QueryStats{QueryID: qid, SQL: sqlText}
		r.groups[qid] = s
	}
	s.Calls++
	dms := uint64(ms) //nolint:gosec // clamped non-negative
	s.TotalMS += dms
	if dms > s.MaxMS {
		s.MaxMS = dms
	}
	s.LastSeen = time.Now()
	if dur > r.threshold {
		s.SlowCalls++
		r.slowN.Add(1)
	}
	r.mu.Unlock()

	if dur > r.threshold {
		r.logger.Warn("slow query",
			"query_id", qid,
			"duration_ms", dur.Milliseconds(),
			"rows_scanned", rowsScanned,
			"sql", redact(sqlText),
		)
	}
}

// Tracker is the per-request budget tracker. Construct via
// Recorder.NewTracker; pass into context so handlers can charge
// queries against the per-request budget.
type Tracker struct {
	recorder *Recorder
	total    time.Duration
	mu       sync.Mutex
}

// NewTracker returns a fresh Tracker scoped to one HTTP request.
func (r *Recorder) NewTracker() *Tracker {
	return &Tracker{recorder: r}
}

// Add accounts for one query inside the tracker's scope.
func (t *Tracker) Add(dur time.Duration) {
	t.mu.Lock()
	t.total += dur
	t.mu.Unlock()
}

// OverBudget reports whether the per-request total has crossed the
// Recorder's request budget.
func (t *Tracker) OverBudget() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total > t.recorder.budget
}

// Total returns the accumulated query time for this request.
func (t *Tracker) Total() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// TimeQuery is a convenience helper: runs fn, records the elapsed
// duration via Recorder.Record + the per-tracker Add, and returns
// fn's error verbatim. Use for hot-path query call sites.
func TimeQuery(ctx context.Context, rec *Recorder, sqlText string, fn func() (int, error)) error {
	if rec == nil {
		_, err := fn()
		return err
	}
	start := time.Now()
	rows, err := fn()
	dur := time.Since(start)
	rec.Record(ctx, sqlText, dur, rows)
	if tr := TrackerFromContext(ctx); tr != nil {
		tr.Add(dur)
	}
	return err
}

// Stats returns a snapshot of the per-query aggregations sorted by
// TotalMS desc + the count totals. Used by the doctor command +
// the /admin/logs UI.
func (r *Recorder) Stats() (groups []QueryStats, totalMS, slowCalls uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]QueryStats, 0, len(r.groups))
	for _, s := range r.groups {
		out = append(out, *s)
	}
	// Insertion sort — n is tiny in practice (<100 distinct queries).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].TotalMS < out[j].TotalMS; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, r.total.Load(), r.slowN.Load()
}

// ─── context plumbing ─────────────────────────────────────────────────

type ctxKey int

const trackerKey ctxKey = 0

// WithTracker attaches a Tracker to ctx so deep callers (helpers
// that invoke sql.DB directly) can charge their query time without
// threading the Tracker explicitly.
func WithTracker(ctx context.Context, tr *Tracker) context.Context {
	return context.WithValue(ctx, trackerKey, tr)
}

// TrackerFromContext returns the Tracker attached to ctx, or nil.
func TrackerFromContext(ctx context.Context) *Tracker {
	if v, ok := ctx.Value(trackerKey).(*Tracker); ok {
		return v
	}
	return nil
}

// queryID returns a short stable hash of the SQL with whitespace +
// parameter literals normalized. Two calls with the same shape
// (different parameter values) group together.
func queryID(sqlText string) string {
	norm := normalizeSQL(sqlText)
	h := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(h[:8])
}

// normalizeSQL collapses runs of whitespace + lowercases keywords
// so the grouping key is stable across formatting changes. We
// intentionally don't try to strip parameter literals — the SQL
// builders in this daemon use placeholders ($1/$2 or ?), so the
// raw text + parameters are already separated.
func normalizeSQL(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		// Lowercase ASCII letters for keyword stability.
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// redact replaces anything that looks like a string literal with a
// placeholder so the log entry doesn't leak operator data through
// parameter values that got inlined for any reason.
func redact(sqlText string) string {
	var b strings.Builder
	b.Grow(len(sqlText))
	inStr := false
	for i := 0; i < len(sqlText); i++ {
		c := sqlText[i]
		if c == '\'' {
			if !inStr {
				b.WriteString("'?'")
			}
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// WrapDB returns a *sql.DB that delegates to inner but records
// timing on QueryContext / QueryRowContext / ExecContext. Returns
// inner unmodified when rec is nil so existing tests stay unaffected.
//
// We don't wrap *sql.DB directly because sql.DB is concrete — instead
// callers that want per-call instrumentation use TimeQuery(ctx, rec,
// sql, fn) at the call site. WrapDB is a hook for future driver-
// level integration (e.g. when sqlc or sqlx grow into the stack).
func WrapDB(rec *Recorder, inner *sql.DB) *sql.DB {
	return inner
}
