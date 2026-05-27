package api

// v1.17 phase 6 — Snapshot API.
//
//   POST /api/v1/snapshots                  body: { "name": "...", "description": "..." }
//     Creates an immutable, named point-in-time view by snapshotting
//     the max(id) of every canonical warehouse table. Returns the
//     full snapshot record including content_hash.
//
//   GET  /api/v1/snapshots                  list every snapshot
//   GET  /api/v1/snapshots/{name}           inspect one
//   GET  /api/v1/snapshots/{name}/findings  paginated findings
//                                            scoped to the snapshot
//   DELETE /api/v1/snapshots/{name}         operator-removed; the
//                                            DB rows themselves stay
//                                            (snapshots are read-only
//                                            views, not table forks)
//
// Snapshots compose with the v1.17 warehouse loaders so an operator
// can `compliancekit warehouse load --to=bigquery --snapshot=q1-2026`
// and get a deterministic bulk load.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

type snapshotRow struct {
	Name            string    `json:"name"`
	ContentHash     string    `json:"content_hash"`
	FindingsCursor  string    `json:"findings_cursor"`
	ResourcesCursor string    `json:"resources_cursor"`
	ScansCursor     string    `json:"scans_cursor"`
	AuditCursor     string    `json:"audit_cursor"`
	Description     string    `json:"description"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedByUserID string    `json:"created_by_user_id,omitempty"`
}

func (a *API) mountSnapshotRoutes(r chi.Router) {
	r.Get("/snapshots", a.scopeGate(auth.ScopeFindingsRead, a.listSnapshots))
	r.Post("/snapshots", a.scopeGate(auth.ScopeSettingsWrite, a.createSnapshot))
	r.Get("/snapshots/{name}", a.scopeGate(auth.ScopeFindingsRead, a.getSnapshot))
	r.Get("/snapshots/{name}/findings", a.scopeGate(auth.ScopeFindingsRead, a.listSnapshotFindings))
	r.Delete("/snapshots/{name}", a.scopeGate(auth.ScopeSettingsWrite, a.deleteSnapshot))
}

type createSnapshotPayload struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (a *API) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var p createSnapshotPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !validSnapshotName(p.Name) {
		http.Error(w, "name must be 3-64 chars [a-z0-9_-] starting with alphanumeric", http.StatusBadRequest)
		return
	}

	// Capture max(id) per table at the moment of snapshot creation.
	// SnapshotCursor uses these as the upper bound on every
	// subsequent read.
	maxFinding := maxString(r.Context(), a.store.DB(), "SELECT COALESCE(MAX(id),'') FROM findings")
	maxResource := maxString(r.Context(), a.store.DB(), "SELECT COALESCE(MAX(id),'') FROM resources")
	maxScan := maxString(r.Context(), a.store.DB(), "SELECT COALESCE(MAX(id),'') FROM scans")
	maxAudit := maxString(r.Context(), a.store.DB(), "SELECT COALESCE(MAX(id),'') FROM audit_log")
	hash := contentHashFor(maxFinding, maxResource, maxScan, maxAudit)
	now := time.Now().UTC()

	sess := auth.FromContext(r.Context())
	createdBy := ""
	if sess != nil {
		createdBy = sess.UserID
	}
	_, err := a.store.DB().ExecContext(r.Context(),
		`INSERT INTO snapshots (name, content_hash, findings_cursor, resources_cursor,
		                        scans_cursor, audit_cursor, description, created_at,
		                        created_by_user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, hash, maxFinding, maxResource, maxScan, maxAudit, p.Description,
		now.Format(time.RFC3339), nullString(createdBy))
	if err != nil {
		// Most likely cause: UNIQUE violation on name.
		http.Error(w, "create snapshot: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(snapshotRow{
		Name:            p.Name,
		ContentHash:     hash,
		FindingsCursor:  maxFinding,
		ResourcesCursor: maxResource,
		ScansCursor:     maxScan,
		AuditCursor:     maxAudit,
		Description:     p.Description,
		CreatedAt:       now,
		CreatedByUserID: createdBy,
	})
}

func (a *API) listSnapshots(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.DB().QueryContext(r.Context(),
		`SELECT name, content_hash, findings_cursor, resources_cursor, scans_cursor,
		        audit_cursor, description, created_at, COALESCE(created_by_user_id,'')
		 FROM snapshots ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]snapshotRow, 0)
	for rows.Next() {
		var s snapshotRow
		var createdAt string
		if err := rows.Scan(&s.Name, &s.ContentHash, &s.FindingsCursor, &s.ResourcesCursor,
			&s.ScansCursor, &s.AuditCursor, &s.Description, &createdAt, &s.CreatedByUserID); err != nil {
			http.Error(w, "scan: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, s)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
}

func (a *API) getSnapshot(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s, err := a.loadSnapshot(r.Context(), name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "snapshot not found", http.StatusNotFound)
			return
		}
		http.Error(w, "load: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func (a *API) listSnapshotFindings(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s, err := a.loadSnapshot(r.Context(), name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "snapshot not found", http.StatusNotFound)
			return
		}
		http.Error(w, "load: "+err.Error(), http.StatusInternalServerError)
		return
	}
	limit := 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}
	rows, err := a.store.DB().QueryContext(r.Context(),
		`SELECT id, scan_id, fingerprint, check_id, severity, status, provider,
		        resource_id, COALESCE(resource_name,''), COALESCE(resource_type,''),
		        COALESCE(message,'')
		 FROM findings
		 WHERE id <= ?
		 ORDER BY id
		 LIMIT ?`, s.FindingsCursor, limit)
	if err != nil {
		http.Error(w, "query: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	type findingRow struct {
		ID           string `json:"id"`
		ScanID       string `json:"scan_id"`
		Fingerprint  string `json:"fingerprint"`
		CheckID      string `json:"check_id"`
		Severity     string `json:"severity"`
		Status       string `json:"status"`
		Provider     string `json:"provider"`
		ResourceID   string `json:"resource_id"`
		ResourceName string `json:"resource_name,omitempty"`
		ResourceType string `json:"resource_type,omitempty"`
		Message      string `json:"message,omitempty"`
	}
	out := make([]findingRow, 0)
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Fingerprint, &f.CheckID, &f.Severity,
			&f.Status, &f.Provider, &f.ResourceID, &f.ResourceName, &f.ResourceType, &f.Message); err != nil {
			http.Error(w, "scan: "+err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, f)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"snapshot": s.Name,
		"items":    out,
		"cursor":   s.FindingsCursor,
	})
}

func (a *API) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	res, err := a.store.DB().ExecContext(r.Context(),
		`DELETE FROM snapshots WHERE name = ?`, name)
	if err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"deleted": n})
}

func (a *API) loadSnapshot(ctx context.Context, name string) (snapshotRow, error) {
	var s snapshotRow
	var createdAt string
	row := a.store.DB().QueryRowContext(ctx,
		`SELECT name, content_hash, findings_cursor, resources_cursor, scans_cursor,
		        audit_cursor, description, created_at, COALESCE(created_by_user_id,'')
		 FROM snapshots WHERE name = ?`, name)
	if err := row.Scan(&s.Name, &s.ContentHash, &s.FindingsCursor, &s.ResourcesCursor,
		&s.ScansCursor, &s.AuditCursor, &s.Description, &createdAt, &s.CreatedByUserID); err != nil {
		return snapshotRow{}, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return s, nil
}

func maxString(ctx context.Context, db *sql.DB, query string) string {
	var v string
	_ = db.QueryRowContext(ctx, query).Scan(&v)
	return v
}

func contentHashFor(findings, resources, scans, audit string) string {
	h := sha256.Sum256([]byte(findings + "|" + resources + "|" + scans + "|" + audit))
	return hex.EncodeToString(h[:])
}

func validSnapshotName(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	if !isAlnum(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isAlnum(c) || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
