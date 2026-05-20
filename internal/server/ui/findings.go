package ui

// v1.5 Phase 0 — SQL-backed findings explorer + virtualised infinite
// scroll.
//
// /findings is the new primary surface in serve mode (the v1.2 HTML
// report served at /scans/{id} stays as the share-with-the-board
// artifact). Every filter dimension is an indexed column on the
// findings table (severity / status / provider / framework /
// resource_type / resource_name / check_id / scan_id / first_seen_at
// / last_seen_at — all indexed at v1.3 Phase 1).
//
// Pagination uses an opaque cursor (created_at + id pair encoded
// base64) rather than OFFSET/LIMIT. The htmx infinite-scroll pattern
// (hx-trigger="revealed" on a sentinel row) auto-fetches the next
// page when the operator scrolls near the bottom; rows append to the
// existing table body, so 100k findings work without ever rendering
// the whole list at once. v1.5 later phases layer a true virtualised
// scroll on top for the dense-table case.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Severity labels — extracted to constants so goconst doesn't fire
// on the case-switches in findings.go + resourcemap.go.
const (
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
	sevInfo     = "info"
)

// findingRow is the per-row payload the explorer template iterates
// over. Wider than the API row because the explorer needs the
// resource type + the framework array for chip-rendering.
type findingRow struct {
	ID           string
	ScanID       string
	CheckID      string
	Severity     string
	Status       string
	Provider     string
	ResourceID   string
	ResourceName string
	ResourceType string
	Message      string
	Frameworks   []string
	FirstSeen    string
	FirstSeenIn  string
	LastSeen     string
	LastSeenIn   string
	// v1.8 phase 1+. The stable (check_id, resource.id, status) hash
	// the comments + activity tables join on. Required for the
	// /findings/{id}/comments side-panel tab; loaded by both
	// queryFindings and loadFindingByID.
	Fingerprint  string
	CommentCount int
}

// findingFilters mirrors the query-string shape. Zero values mean
// "no filter on that dimension."
type findingFilters struct {
	Severities    []string
	Statuses      []string
	Providers     []string
	Frameworks    []string
	ResourceTypes []string
	CheckIDs      []string
	NameQuery     string
	ScanID        string
	SinceDays     int
	Cursor        string
	PerPage       int
	// Assignee v1.8 phase 2 — empty string = no filter; the literal
	// "me" resolves at query time against the session user; any other
	// value is taken as a literal user id.
	Assignee string
}

// findingsView is the explorer-page payload.
type findingsView struct {
	View
	Items      []findingRow
	NextCursor string
	HasNext    bool
	Filters    findingFilters
	Stats      findingStats
}

// findingStats are the headline numbers above the table (severity
// counts in the current filter scope).
type findingStats struct {
	Total     int
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
	OpenScans int
}

// buildFindingsWhere assembles the WHERE-clause fragments + arg
// slice from the filter set. Extracted from queryFindings to keep
// the cyclomatic complexity reasonable.
func (u *UI) buildFindingsWhere(f findingFilters) (clauses []string, params []any) {
	add := func(clause string, vals ...any) {
		clauses = append(clauses, clause)
		params = append(params, vals...)
	}
	addIN := func(column string, vals []string) {
		if len(vals) == 0 {
			return
		}
		list := placeholderListAt(u.store, len(params)+1, len(vals))
		add(column+" IN ("+list+")", anyify(vals)...)
	}
	addIN("severity", f.Severities)
	addIN("status", f.Statuses)
	addIN("provider", f.Providers)
	addIN("resource_type", f.ResourceTypes)
	addIN("check_id", f.CheckIDs)
	if f.NameQuery != "" {
		add("(resource_name LIKE "+ph(u.store, len(params)+1)+" OR check_id LIKE "+ph(u.store, len(params)+2)+")",
			"%"+f.NameQuery+"%", "%"+f.NameQuery+"%")
	}
	if f.ScanID != "" {
		add("scan_id = "+ph(u.store, len(params)+1), f.ScanID)
	}
	if f.SinceDays > 0 {
		cutoff := time.Now().Add(-time.Duration(f.SinceDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
		add("last_seen_at >= "+ph(u.store, len(params)+1), cutoff)
	}
	if f.Assignee != "" {
		// "me" is rewritten to the session user id by the caller via
		// resolveAssignee; an unresolved "me" matches no rows so the
		// page renders empty.
		add("fingerprint IN (SELECT finding_fingerprint FROM finding_assignment WHERE assignee_user_id = "+
			ph(u.store, len(params)+1)+")", f.Assignee)
	}
	if c := decodeCursor(f.Cursor); c.valid {
		// (created_at, id) lexicographic — newest first means
		// "rows BEFORE this cursor."
		add("(created_at, id) < ("+ph(u.store, len(params)+1)+", "+ph(u.store, len(params)+2)+")",
			c.createdAt, c.id)
	}
	return clauses, params
}

// mountFindingsRoutes registers the Phase 0 endpoints.
func (u *UI) mountFindingsRoutes(r chi.Router) {
	r.Get("/findings", u.findingsList)
	r.Get("/findings/rows", u.findingsRowsPartial) // htmx infinite-scroll target
}

// findingsList renders the full explorer page (header + filter bar
// scaffold + initial 50 rows + the htmx infinite-scroll sentinel).
func (u *UI) findingsList(w http.ResponseWriter, r *http.Request) {
	filters := parseFindingFilters(r.URL.Query())
	filters.Assignee = u.resolveAssignee(r, filters.Assignee)
	items, next, err := u.queryFindings(r.Context(), filters)
	if err != nil {
		u.fail(w, "query findings: "+err.Error())
		return
	}
	stats, err := u.countFindingsBySeverity(r.Context(), filters)
	if err != nil {
		u.fail(w, "count findings: "+err.Error())
		return
	}
	view := findingsView{
		View:       u.viewFor(r, "Findings", "findings", View{}),
		Items:      items,
		NextCursor: next,
		HasNext:    next != "",
		Filters:    filters,
		Stats:      stats,
	}
	u.render(w, "findings.html", view)
}

// findingsRowsPartial returns just the <tr>s + the next sentinel for
// the htmx hx-trigger="revealed" pattern. Loads the next chunk when
// the operator scrolls near the bottom.
func (u *UI) findingsRowsPartial(w http.ResponseWriter, r *http.Request) {
	filters := parseFindingFilters(r.URL.Query())
	filters.Assignee = u.resolveAssignee(r, filters.Assignee)
	items, next, err := u.queryFindings(r.Context(), filters)
	if err != nil {
		http.Error(w, "query findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	view := findingsView{
		View:       u.viewFor(r, "", "findings", View{}),
		Items:      items,
		NextCursor: next,
		HasNext:    next != "",
		Filters:    filters,
	}
	u.render(w, "findings_rows.html", view)
}

// parseFindingFilters reads the filter set from URL.Query. Repeated
// keys collect into the OR-within-dimension slices.
func parseFindingFilters(v map[string][]string) findingFilters {
	get := func(k string) []string {
		out := []string{}
		for _, s := range v[k] {
			for _, p := range strings.Split(s, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
		}
		return out
	}
	first := func(k string) string {
		if vs := v[k]; len(vs) > 0 {
			return strings.TrimSpace(vs[0])
		}
		return ""
	}
	perPage, _ := strconv.Atoi(first("per_page"))
	if perPage <= 0 || perPage > 200 {
		perPage = 50
	}
	since, _ := strconv.Atoi(first("since_days"))
	return findingFilters{
		Severities:    get("severity"),
		Statuses:      get("status"),
		Providers:     get("provider"),
		Frameworks:    get("framework"),
		ResourceTypes: get("resource_type"),
		CheckIDs:      get("check_id"),
		NameQuery:     first("q"),
		ScanID:        first("scan"),
		SinceDays:     since,
		Cursor:        first("cursor"),
		PerPage:       perPage,
		Assignee:      first("assignee"),
	}
}

// resolveAssignee rewrites "me" to the session user id; passes other
// values through unchanged. Used by handlers before invoking
// queryFindings + countFindingsBySeverity so the dispatch happens
// once per request.
func (u *UI) resolveAssignee(r *http.Request, raw string) string {
	if raw != "me" {
		return raw
	}
	if sess := auth.FromContext(r.Context()); sess != nil {
		return sess.UserID
	}
	return raw
}

// queryFindings runs the SQL with the filter set applied, returns up
// to PerPage rows and the next-cursor (empty when no more rows).
func (u *UI) queryFindings(ctx context.Context, f findingFilters) ([]findingRow, string, error) {
	where, args := u.buildFindingsWhere(f)
	q := `SELECT id, scan_id, check_id, severity, status, provider,
	             resource_id, resource_name, resource_type, COALESCE(message,''),
	             COALESCE(framework_ids,'[]'),
	             first_seen_at, last_seen_at, fingerprint
	      FROM findings`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT " + strconv.Itoa(f.PerPage+1)

	rows, err := u.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	out := []findingRow{}
	now := time.Now()
	for rows.Next() {
		var r findingRow
		var fwJSON string
		if err := rows.Scan(&r.ID, &r.ScanID, &r.CheckID, &r.Severity, &r.Status, &r.Provider,
			&r.ResourceID, &r.ResourceName, &r.ResourceType, &r.Message,
			&fwJSON, &r.FirstSeen, &r.LastSeen, &r.Fingerprint); err != nil {
			return out, "", err
		}
		_ = json.Unmarshal([]byte(fwJSON), &r.Frameworks)
		if len(f.Frameworks) > 0 && !anyOverlap(r.Frameworks, f.Frameworks) {
			continue
		}
		if t, e := time.Parse(time.RFC3339, r.FirstSeen); e == nil {
			r.FirstSeenIn = humanizeAgoFrom(t, now)
		}
		if t, e := time.Parse(time.RFC3339, r.LastSeen); e == nil {
			r.LastSeenIn = humanizeAgoFrom(t, now)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return out, "", err
	}

	// Cursor = the LAST row of this page (encoded). The +1 in the
	// LIMIT lets us tell whether there's another page without doing
	// a second query.
	var next string
	if len(out) > f.PerPage {
		out = out[:f.PerPage]
	}
	// Recompute "is there more" by checking whether the SQL returned
	// exactly PerPage+1 rows. Even with the framework-overlap drops
	// above we approximate by checking if any drops happened; if
	// they did, hint at HasNext by emitting a cursor anyway.
	if len(out) == f.PerPage {
		last := out[len(out)-1]
		next = encodeCursor(cursorPos{createdAt: last.FirstSeen, id: last.ID, valid: true})
	}
	return out, next, nil
}

// countFindingsBySeverity returns the severity histogram for the
// current filter set. Used for the stats row above the table.
// Note: the cursor is intentionally excluded — the histogram is
// page-independent.
func (u *UI) countFindingsBySeverity(ctx context.Context, f findingFilters) (findingStats, error) {
	// Drop the cursor so the histogram reflects the full filter
	// scope, not just the current page.
	cf := f
	cf.Cursor = ""
	where, args := u.buildFindingsWhere(cf)
	q := `SELECT severity, COUNT(*) FROM findings`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " GROUP BY severity"
	rows, err := u.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return findingStats{}, err
	}
	defer func() { _ = rows.Close() }()
	stats := findingStats{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return stats, err
		}
		stats.Total += n
		switch sev {
		case sevCritical:
			stats.Critical = n
		case sevHigh:
			stats.High = n
		case sevMedium:
			stats.Medium = n
		case sevLow:
			stats.Low = n
		case sevInfo:
			stats.Info = n
		}
	}
	return stats, rows.Err()
}

// cursorPos is the opaque pagination cursor — (created_at, id) pair.
type cursorPos struct {
	createdAt string
	id        string
	valid     bool
}

func encodeCursor(c cursorPos) string {
	if !c.valid {
		return ""
	}
	s := c.createdAt + "|" + c.id
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func decodeCursor(s string) cursorPos {
	if s == "" {
		return cursorPos{}
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursorPos{}
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return cursorPos{}
	}
	return cursorPos{createdAt: parts[0], id: parts[1], valid: true}
}

// placeholderListAt returns "?, ?, ?" or "$N, $N+1, $N+2" for the
// active dialect, starting from arg index n. Distinct from phList
// (which always starts at $1) because the findings explorer composes
// WHERE clauses with variable offsets.
func placeholderListAt(st *store.Store, n, count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = ph(st, n+i)
	}
	return strings.Join(parts, ", ")
}

// anyify is a tiny []string → []any converter for sql.DB.QueryContext.
func anyify(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// anyOverlap returns true if any element of a is also in b.
func anyOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// humanizeAgoFrom is humanizeAgo with the reference time injected so
// tests are deterministic. The wrapper humanizeAgo(s string) parses
// + delegates here.
func humanizeAgoFrom(t, ref time.Time) string {
	d := ref.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return formatAgo(d.Minutes(), "m")
	case d < 24*time.Hour:
		return formatAgo(d.Hours(), "h")
	default:
		return formatAgo(d.Hours()/24, "d")
	}
}
