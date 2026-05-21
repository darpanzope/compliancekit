package api

// v1.11 phase 9 — Streaming NDJSON export.
//
// GET /api/v1/findings.ndjson streams the full filtered set as
// newline-delimited JSON. Each finding is encoded one line at a
// time + flushed so warehouse loaders (v1.17), large client-side
// analytics, and `compliancekit warehouse export` (also v1.17) get
// constant-memory streaming behavior instead of the 50-row page
// shape.
//
// Filters compose with the same query-string convention as
// /api/v1/findings (severity / status / provider / etc.) so callers
// can stream a scoped slice. No pagination, no cursor — the consumer
// gets every matching row.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// streamFindings handles GET /api/v1/findings.ndjson.
func (a *API) streamFindings(w http.ResponseWriter, r *http.Request) {
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
	q := fmt.Sprintf( //nolint:gosec // dialect-aware placeholders; columns are constants
		`SELECT id, scan_id, fingerprint, check_id, severity, status, provider,
		        resource_id, resource_name, resource_type, COALESCE(message,''),
		        framework_ids, first_seen_at, last_seen_at, created_at
		 FROM findings%s ORDER BY created_at DESC, id DESC`, whereSQL)

	rows, err := a.store.DB().QueryContext(r.Context(), q, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "stream findings: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store") // streaming → no caching
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	enc := json.NewEncoder(w)
	rowsWritten := 0
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Fingerprint, &f.CheckID, &f.Severity, &f.Status, &f.Provider,
			&f.ResourceID, &f.ResourceName, &f.ResourceType, &f.Message,
			&f.FrameworkIDs, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt); err != nil {
			// Streaming has already started — best we can do is bail.
			// The truncated body is recoverable from the operator's side
			// (the v1.6 audit-log records the request error).
			return
		}
		f.enrichFromRegistry()
		if err := enc.Encode(f); err != nil {
			return
		}
		rowsWritten++
		// Flush every 100 rows so the consumer sees progress + the
		// daemon's send buffer doesn't grow unbounded on slow clients.
		if rowsWritten%100 == 0 && flusher != nil {
			flusher.Flush()
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
}
