package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/respcache"
	"github.com/darpanzope/compliancekit/internal/server/store"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// scanRow is the JSON shape returned by GET /api/v1/scans and
// GET /api/v1/scans/:id. Fields mirror the scans table; rendered
// with snake_case keys for consistency with the rest of the JSON
// API + compliancekit.yaml.
type scanRow struct {
	ID                 string `json:"id"`
	CreatedAt          string `json:"created_at"`
	StartedAt          string `json:"started_at,omitempty"`
	FinishedAt         string `json:"finished_at,omitempty"`
	Source             string `json:"source"`
	Status             string `json:"status"`
	ProvidersScanned   string `json:"providers_scanned"`
	FrameworksScanned  string `json:"frameworks_scanned"`
	Score              int    `json:"score"`
	Coverage           int    `json:"coverage"`
	TotalFindings      int    `json:"total_findings"`
	ActionableFindings int    `json:"actionable_findings"`
	DurationMS         int    `json:"duration_ms,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`
}

// page wraps a list response with pagination metadata.
type page[T any] struct {
	Items   []T `json:"items"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

// listScans returns the paginated scan history.
//
// v1.11 phase 0 — Cursor mode is the new default; legacy ?page= still
// works for one minor release. Cursor encodes `(created_at, id)` of
// the last row of the previous page + the next query selects rows
// strictly after that pair via the idx_scans_created_at index.
func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("page") != "" {
		a.listScansLegacy(w, r)
		return
	}
	cursor, per, _ := parseCursorMode(r)
	ctx := r.Context()
	args := []any{}
	where := ""
	if !cursor.IsZero() {
		// DESC order: next page = rows with (created_at, id) strictly
		// less than the cursor's tuple.
		where = " WHERE (created_at, id) < (" + a.ph(1) + ", " + a.ph(2) + ")"
		args = []any{cursor.SortKey, cursor.ID}
	}
	args = append(args, per+1) // +1 to detect "more"
	q := fmt.Sprintf(          //nolint:gosec // placeholders only; no user input
		`SELECT id, created_at, COALESCE(started_at,''), COALESCE(finished_at,''), source, status,
		        providers_scanned, frameworks_scanned, COALESCE(score, 0), COALESCE(coverage, 0),
		        total_findings, actionable_findings, COALESCE(duration_ms, 0), COALESCE(error_message,'')
		 FROM scans%s ORDER BY created_at DESC, id DESC LIMIT %s`,
		where, a.ph(len(args)))
	rows, err := a.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list scans: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]scanRow, 0, per)
	for rows.Next() {
		var s scanRow
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Source, &s.Status,
			&s.ProvidersScanned, &s.FrameworksScanned, &s.Score, &s.Coverage,
			&s.TotalFindings, &s.ActionableFindings, &s.DurationMS, &s.ErrorMessage); err != nil {
			respondError(w, http.StatusInternalServerError, "scan row: "+err.Error())
			return
		}
		items = append(items, s)
	}
	var next string
	if len(items) > per {
		items = items[:per]
		last := items[len(items)-1]
		next = Cursor{SortKey: last.CreatedAt, ID: last.ID}.Encode()
	}
	respondJSON(w, r, http.StatusOK, pageCursor[scanRow]{Items: items, NextCursor: next, PerPage: per})
}

// listScansLegacy is the v1.0-v1.10 OFFSET-based listScans path.
// Kept for one minor release so existing clients that send
// ?page=N&per_page=M don't break unexpectedly. Removed at v1.12.
func (a *API) listScansLegacy(w http.ResponseWriter, r *http.Request) {
	pageN, per := parsePage(r)
	offset := (pageN - 1) * per
	ctx := r.Context()
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, created_at, COALESCE(started_at,''), COALESCE(finished_at,''), source, status,
		        providers_scanned, frameworks_scanned, COALESCE(score, 0), COALESCE(coverage, 0),
		        total_findings, actionable_findings, COALESCE(duration_ms, 0), COALESCE(error_message,'')
		 FROM scans ORDER BY created_at DESC LIMIT %s OFFSET %s`,
		a.ph(1), a.ph(2))
	rows, err := a.store.DB().QueryContext(ctx, q, per, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list scans: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]scanRow, 0, per)
	for rows.Next() {
		var s scanRow
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Source, &s.Status,
			&s.ProvidersScanned, &s.FrameworksScanned, &s.Score, &s.Coverage,
			&s.TotalFindings, &s.ActionableFindings, &s.DurationMS, &s.ErrorMessage); err != nil {
			respondError(w, http.StatusInternalServerError, "scan row: "+err.Error())
			return
		}
		items = append(items, s)
	}
	total := a.count(ctx, "scans", "")
	respondJSON(w, r, http.StatusOK, page[scanRow]{Items: items, Page: pageN, PerPage: per, Total: total})
}

// getScan returns a single scan by ID.
func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, created_at, COALESCE(started_at,''), COALESCE(finished_at,''), source, status,
		        providers_scanned, frameworks_scanned, COALESCE(score, 0), COALESCE(coverage, 0),
		        total_findings, actionable_findings, COALESCE(duration_ms, 0), COALESCE(error_message,'')
		 FROM scans WHERE id = %s`, a.ph(1))
	var s scanRow
	err := a.store.DB().QueryRowContext(r.Context(), q, id).Scan(
		&s.ID, &s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Source, &s.Status,
		&s.ProvidersScanned, &s.FrameworksScanned, &s.Score, &s.Coverage,
		&s.TotalFindings, &s.ActionableFindings, &s.DurationMS, &s.ErrorMessage)
	if errors.Is(err, sql.ErrNoRows) {
		respondError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "get scan: "+err.Error())
		return
	}
	respondJSON(w, r, http.StatusOK, s)
}

// findingRow is the JSON shape returned by /api/v1/findings + nested
// /api/v1/scans/:id/findings.
//
// v1.5.1 F22: the CheckTitle / CheckDescription / CheckRemediation
// fields are populated from the in-binary registry via LookupCheck
// at marshal time. Downstream consumers (CI integrations, third-
// party dashboards, the v1.5 Studio's external clients) used to
// see opaque CheckID strings; now the JSON carries the human-
// facing metadata the registry holds without an extra round-trip.
type findingRow struct {
	ID               string `json:"id"`
	ScanID           string `json:"scan_id"`
	Fingerprint      string `json:"fingerprint"`
	CheckID          string `json:"check_id"`
	CheckTitle       string `json:"check_title,omitempty"`
	CheckDescription string `json:"check_description,omitempty"`
	CheckRemediation string `json:"check_remediation,omitempty"`
	Severity         string `json:"severity"`
	Status           string `json:"status"`
	Provider         string `json:"provider"`
	ResourceID       string `json:"resource_id"`
	ResourceName     string `json:"resource_name"`
	ResourceType     string `json:"resource_type"`
	Message          string `json:"message,omitempty"`
	FrameworkIDs     string `json:"framework_ids"`
	FirstSeenAt      string `json:"first_seen_at"`
	LastSeenAt       string `json:"last_seen_at"`
	CreatedAt        string `json:"created_at"`
}

// enrichFromRegistry populates the CheckTitle / CheckDescription /
// CheckRemediation fields from the in-binary check registry. v1.5.1
// F22. Silently no-ops for check IDs the daemon's registry doesn't
// know (e.g. CLI-pushed findings from a newer compliancekit binary
// than the daemon's).
func (f *findingRow) enrichFromRegistry() {
	check, ok := compliancekit.LookupCheck(f.CheckID)
	if !ok {
		return
	}
	f.CheckTitle = check.Title
	f.CheckDescription = check.Description
	f.CheckRemediation = check.Remediation
}

// listFindings returns the paginated global findings list with
// optional filter knobs that v1.5's explorer will rely on more
// heavily.
//
// v1.11 phase 0 — Cursor mode default; legacy ?page= still works.
// Cursor encodes `(created_at, id)`. Filters compose with the
// cursor predicate via a WHERE-AND chain.
func (a *API) listFindings(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("page") != "" {
		a.listFindingsLegacy(w, r)
		return
	}
	cursor, per, _ := parseCursorMode(r)

	// v1.11 phase 6 — LRU cache lookup. Per-user scope so admin
	// + non-admin queries don't collide. Skipped when the cache
	// isn't wired into the API.
	cacheKey := ""
	if a.cache != nil {
		userID := ""
		if sess := auth.FromContext(r.Context()); sess != nil {
			userID = sess.UserID
		}
		cacheKey = respcache.KeyFor("findings:", r.URL.RawQuery, cursor.Encode(), userID)
		if entry, hit := a.cache.Get(cacheKey); hit {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", entry.ETag)
			w.Header().Set("X-Cache", "hit")
			_, _ = w.Write(entry.Body)
			return
		}
	}

	// Filter parser: each of these maps to a column.
	type filterDef struct{ key, col string }
	filters := []filterDef{
		{"severity", "severity"},
		{"status", "status"},
		{"provider", "provider"},
		{"resource_type", "resource_type"},
		{"check_id", "check_id"},
		{"scan_id", "scan_id"},
	}
	var (
		where []string
		args  []any
		i     = 1
	)
	for _, f := range filters {
		if v := r.URL.Query().Get(f.key); v != "" {
			where = append(where, f.col+" = "+a.ph(i))
			args = append(args, v)
			i++
		}
	}
	if !cursor.IsZero() {
		where = append(where, "(created_at, id) < ("+a.ph(i)+", "+a.ph(i+1)+")")
		args = append(args, cursor.SortKey, cursor.ID)
		i += 2
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, per+1)
	q := fmt.Sprintf( //nolint:gosec // dialect-aware placeholders; column names are this package's constants
		`SELECT id, scan_id, fingerprint, check_id, severity, status, provider,
		        resource_id, resource_name, resource_type, COALESCE(message,''),
		        framework_ids, first_seen_at, last_seen_at, created_at
		 FROM findings%s ORDER BY created_at DESC, id DESC LIMIT %s`,
		whereSQL, a.ph(i))

	rows, err := a.store.DB().QueryContext(r.Context(), q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list findings: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]findingRow, 0, per)
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Fingerprint, &f.CheckID, &f.Severity, &f.Status, &f.Provider,
			&f.ResourceID, &f.ResourceName, &f.ResourceType, &f.Message,
			&f.FrameworkIDs, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "finding row: "+err.Error())
			return
		}
		f.enrichFromRegistry()
		items = append(items, f)
	}
	var next string
	if len(items) > per {
		items = items[:per]
		last := items[len(items)-1]
		next = Cursor{SortKey: last.CreatedAt, ID: last.ID}.Encode()
	}
	payload := pageCursor[findingRow]{Items: items, NextCursor: next, PerPage: per}
	// v1.11 phase 6 — populate the cache. Cached body is the
	// canonical JSON serialization the response writes anyway;
	// the cache hit path mirrors the same Content-Type + ETag.
	if cacheKey != "" {
		if body, err := json.Marshal(payload); err == nil {
			a.cache.Set(cacheKey, body, "")
		}
	}
	respondJSON(w, r, http.StatusOK, payload)
}

// listFindingsLegacy is the v1.0-v1.10 OFFSET path. Removed at v1.12.
func (a *API) listFindingsLegacy(w http.ResponseWriter, r *http.Request) {
	pageN, per := parsePage(r)
	offset := (pageN - 1) * per

	type filterDef struct{ key, col string }
	filters := []filterDef{
		{"severity", "severity"},
		{"status", "status"},
		{"provider", "provider"},
		{"resource_type", "resource_type"},
		{"check_id", "check_id"},
		{"scan_id", "scan_id"},
	}
	var (
		where []string
		args  []any
		i     = 1
	)
	for _, f := range filters {
		if v := r.URL.Query().Get(f.key); v != "" {
			where = append(where, f.col+" = "+a.ph(i))
			args = append(args, v)
			i++
		}
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	q := fmt.Sprintf( //nolint:gosec // dialect-aware placeholders; column names are this package's constants
		`SELECT id, scan_id, fingerprint, check_id, severity, status, provider,
		        resource_id, resource_name, resource_type, COALESCE(message,''),
		        framework_ids, first_seen_at, last_seen_at, created_at
		 FROM findings%s ORDER BY created_at DESC LIMIT %s OFFSET %s`,
		whereSQL, a.ph(i), a.ph(i+1))
	args = append(args, per, offset)

	rows, err := a.store.DB().QueryContext(r.Context(), q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list findings: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]findingRow, 0, per)
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Fingerprint, &f.CheckID, &f.Severity, &f.Status, &f.Provider,
			&f.ResourceID, &f.ResourceName, &f.ResourceType, &f.Message,
			&f.FrameworkIDs, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "finding row: "+err.Error())
			return
		}
		f.enrichFromRegistry()
		items = append(items, f)
	}
	total := a.count(r.Context(), "findings", whereSQL, args[:i-1]...)
	respondJSON(w, r, http.StatusOK, page[findingRow]{Items: items, Page: pageN, PerPage: per, Total: total})
}

// listScanFindings is the scoped-to-scan variant: GET
// /api/v1/scans/:id/findings.
func (a *API) listScanFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Reuse listFindings logic by forcing scan_id into the query.
	q := r.URL.Query()
	q.Set("scan_id", id)
	r.URL.RawQuery = q.Encode()
	a.listFindings(w, r)
}

// getFinding returns a single finding by ID.
func (a *API) getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, scan_id, fingerprint, check_id, severity, status, provider,
		        resource_id, resource_name, resource_type, COALESCE(message,''),
		        framework_ids, first_seen_at, last_seen_at, created_at
		 FROM findings WHERE id = %s`, a.ph(1))
	var f findingRow
	err := a.store.DB().QueryRowContext(r.Context(), q, id).Scan(
		&f.ID, &f.ScanID, &f.Fingerprint, &f.CheckID, &f.Severity, &f.Status, &f.Provider,
		&f.ResourceID, &f.ResourceName, &f.ResourceType, &f.Message,
		&f.FrameworkIDs, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		respondError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "get finding: "+err.Error())
		return
	}
	f.enrichFromRegistry()
	respondJSON(w, r, http.StatusOK, f)
}

// resourceRow is the JSON shape for /api/v1/resources.
type resourceRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
}

// listResources returns the paginated resource inventory.
//
// v1.11 phase 0 — Cursor mode default; legacy ?page= still works.
// Cursor encodes `(last_seen_at, id)`.
func (a *API) listResources(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("page") != "" {
		a.listResourcesLegacy(w, r)
		return
	}
	cursor, per, _ := parseCursorMode(r)
	args := []any{}
	where := ""
	if !cursor.IsZero() {
		where = " WHERE (last_seen_at, id) < (" + a.ph(1) + ", " + a.ph(2) + ")"
		args = []any{cursor.SortKey, cursor.ID}
	}
	args = append(args, per+1)
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, type, provider, first_seen_at, last_seen_at
		 FROM resources%s ORDER BY last_seen_at DESC, id DESC LIMIT %s`,
		where, a.ph(len(args)))
	rows, err := a.store.DB().QueryContext(r.Context(), q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list resources: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]resourceRow, 0, per)
	for rows.Next() {
		var res resourceRow
		if err := rows.Scan(&res.ID, &res.Name, &res.Type, &res.Provider, &res.FirstSeenAt, &res.LastSeenAt); err != nil {
			respondError(w, http.StatusInternalServerError, "resource row: "+err.Error())
			return
		}
		items = append(items, res)
	}
	var next string
	if len(items) > per {
		items = items[:per]
		last := items[len(items)-1]
		next = Cursor{SortKey: last.LastSeenAt, ID: last.ID}.Encode()
	}
	respondJSON(w, r, http.StatusOK, pageCursor[resourceRow]{Items: items, NextCursor: next, PerPage: per})
}

// listResourcesLegacy is the v1.0-v1.10 OFFSET path. Removed at v1.12.
func (a *API) listResourcesLegacy(w http.ResponseWriter, r *http.Request) {
	pageN, per := parsePage(r)
	offset := (pageN - 1) * per
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, type, provider, first_seen_at, last_seen_at
		 FROM resources ORDER BY last_seen_at DESC LIMIT %s OFFSET %s`,
		a.ph(1), a.ph(2))
	rows, err := a.store.DB().QueryContext(r.Context(), q, per, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list resources: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]resourceRow, 0, per)
	for rows.Next() {
		var res resourceRow
		if err := rows.Scan(&res.ID, &res.Name, &res.Type, &res.Provider, &res.FirstSeenAt, &res.LastSeenAt); err != nil {
			respondError(w, http.StatusInternalServerError, "resource row: "+err.Error())
			return
		}
		items = append(items, res)
	}
	respondJSON(w, r, http.StatusOK, page[resourceRow]{Items: items, Page: pageN, PerPage: per, Total: a.count(r.Context(), "resources", "")})
}

// getResource returns one resource by ID.
func (a *API) getResource(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, name, type, provider, first_seen_at, last_seen_at
		 FROM resources WHERE id = %s`, a.ph(1))
	var res resourceRow
	err := a.store.DB().QueryRowContext(r.Context(), q, id).Scan(
		&res.ID, &res.Name, &res.Type, &res.Provider, &res.FirstSeenAt, &res.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		respondError(w, http.StatusNotFound, "resource not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "get resource: "+err.Error())
		return
	}
	respondJSON(w, r, http.StatusOK, res)
}

// providerRow is what /api/v1/providers returns. Lists every
// configured provider with its current auth status.
type providerRow struct {
	ID              string `json:"id"`
	Enabled         bool   `json:"enabled"`
	LastAuthCheckAt string `json:"last_auth_check_at,omitempty"`
	LastAuthStatus  string `json:"last_auth_status,omitempty"`
	LastAuthError   string `json:"last_auth_error,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}

func (a *API) listProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.DB().QueryContext(r.Context(),
		`SELECT id, enabled, COALESCE(last_auth_check_at,''), COALESCE(last_auth_status,''), COALESCE(last_auth_error,''), updated_at
		 FROM providers ORDER BY id ASC`)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list providers: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]providerRow, 0, 8)
	for rows.Next() {
		var p providerRow
		var enabled int
		if err := rows.Scan(&p.ID, &enabled, &p.LastAuthCheckAt, &p.LastAuthStatus, &p.LastAuthError, &p.UpdatedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "provider row: "+err.Error())
			return
		}
		p.Enabled = enabled != 0
		items = append(items, p)
	}
	respondJSON(w, r, http.StatusOK, page[providerRow]{Items: items, Page: 1, PerPage: len(items), Total: len(items)})
}

// checkRow is the JSON shape returned by /api/v1/checks. Pulled
// straight from the compiled-in registry rather than the DB so the
// list always reflects the active binary.
type checkRow struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Provider    string   `json:"provider"`
	Service     string   `json:"service,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// listChecks reads from compliancekit.RegisteredChecks() and
// overlays the per-check enabled/disabled state from the
// checks_state table.
func (a *API) listChecks(w http.ResponseWriter, r *http.Request) {
	checks := compliancekit.RegisteredChecks()
	overrides, err := a.checkOverrides(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "load check overrides: "+err.Error())
		return
	}

	// Optional filters: ?provider=, ?framework=, ?severity=
	wantProvider := r.URL.Query().Get("provider")
	wantSeverity := r.URL.Query().Get("severity")
	items := make([]checkRow, 0, len(checks))
	for _, c := range checks {
		if wantProvider != "" && c.Provider != wantProvider {
			continue
		}
		if wantSeverity != "" && c.Severity.String() != wantSeverity {
			continue
		}
		enabled := true
		if v, ok := overrides[c.ID]; ok {
			enabled = v
		}
		items = append(items, checkRow{
			ID: c.ID, Title: c.Title, Description: c.Description,
			Severity: c.Severity.String(), Provider: c.Provider,
			Service: c.Service, Resource: c.ResourceType, Tags: c.Tags, Enabled: enabled,
		})
	}
	respondJSON(w, r, http.StatusOK, page[checkRow]{Items: items, Page: 1, PerPage: len(items), Total: len(items)})
}

// checkOverrides reads checks_state into a map[checkID]enabled. An
// absent row means "use shipped default (enabled)".
func (a *API) checkOverrides(ctx context.Context) (map[string]bool, error) {
	rows, err := a.store.DB().QueryContext(ctx, `SELECT check_id, enabled FROM checks_state`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var e int
		if err := rows.Scan(&id, &e); err != nil {
			return nil, err
		}
		out[id] = e != 0
	}
	return out, rows.Err()
}

// waiverRow is the JSON shape returned by /api/v1/waivers.
type waiverRow struct {
	ID         string `json:"id"`
	CheckID    string `json:"check_id"`
	ResourceID string `json:"resource_id"`
	Reason     string `json:"reason"`
	Approver   string `json:"approver"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

func (a *API) listWaivers(w http.ResponseWriter, r *http.Request) {
	pageN, per := parsePage(r)
	offset := (pageN - 1) * per
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, check_id, resource_id, reason, approver, created_at,
		        COALESCE(expires_at,''), COALESCE(revoked_at,'')
		 FROM waivers ORDER BY created_at DESC LIMIT %s OFFSET %s`,
		a.ph(1), a.ph(2))
	rows, err := a.store.DB().QueryContext(r.Context(), q, per, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list waivers: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	items := make([]waiverRow, 0, per)
	for rows.Next() {
		var wv waiverRow
		if err := rows.Scan(&wv.ID, &wv.CheckID, &wv.ResourceID, &wv.Reason, &wv.Approver, &wv.CreatedAt, &wv.ExpiresAt, &wv.RevokedAt); err != nil {
			respondError(w, http.StatusInternalServerError, "waiver row: "+err.Error())
			return
		}
		items = append(items, wv)
	}
	respondJSON(w, r, http.StatusOK, page[waiverRow]{Items: items, Page: pageN, PerPage: per, Total: a.count(r.Context(), "waivers", "")})
}

// count runs SELECT COUNT(*) FROM <table><whereSQL> and returns the
// scalar. Best-effort; on error returns 0 (so list endpoints don't
// fail just because counting failed).
func (a *API) count(ctx context.Context, table, whereSQL string, args ...any) int {
	q := "SELECT COUNT(*) FROM " + table + whereSQL //nolint:gosec // table from constants; whereSQL composed via placeholder()
	var n int
	if err := a.store.DB().QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

// ph returns the dialect-aware placeholder for arg N.
func (a *API) ph(n int) string {
	if a.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}
