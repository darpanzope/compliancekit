package ui

import (
	"encoding/csv"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// v1.19 phase 8 — bulk triage actions + inline note edit.
//
// The findings explorer's bulk-actions bar posts here with a set of
// finding ids; the inline-edit note posts a single finding's note.
// Every mutation appends a v1.12 hash-chained audit_log entry so the
// optimistic UI reconciles against a durable record.

const maxBulkIDs = 1000

func (u *UI) mountFindingsBulkRoutes(r chi.Router) {
	r.Post("/findings/bulk", u.findingsBulk)
	r.Post("/findings/{id}/note", u.findingNote)
}

// findingsBulk applies action to the posted finding ids. Acknowledge /
// resolve / reopen flip triage_status; assign claims the findings for
// the current user; waive writes a waiver per finding; export streams a
// CSV. Each action appends one audit_log entry per finding.
func (u *UI) findingsBulk(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	ids := r.Form["id"]
	if len(ids) == 0 {
		http.Error(w, "no findings selected", http.StatusBadRequest)
		return
	}
	if len(ids) > maxBulkIDs {
		ids = ids[:maxBulkIDs]
	}

	switch action {
	case "acknowledge":
		u.bulkSetTriage(r, ids, "acknowledged", "finding.acknowledged")
	case "resolve":
		u.bulkSetTriage(r, ids, "resolved", "finding.resolved")
	case "reopen":
		u.bulkSetTriage(r, ids, "open", "finding.reopened")
	case "assign":
		u.bulkAssign(r, ids, sess.UserID)
	case "waive":
		u.bulkWaive(r, ids, sess.UserID)
	case "export":
		u.bulkExportCSV(w, r, ids)
		return // export writes its own response
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	// Non-export actions redirect back to the explorer (the optimistic
	// UI has already updated locally; this reconciles on full reload).
	http.Redirect(w, r, "/findings", http.StatusSeeOther)
}

func (u *UI) bulkSetTriage(r *http.Request, ids []string, status, action string) {
	ctx := r.Context()
	q := `UPDATE findings SET triage_status = ` + ph(u.store, 1) + ` WHERE id = ` + ph(u.store, 2)
	for _, id := range ids {
		if _, err := u.store.DB().ExecContext(ctx, q, status, id); err != nil {
			continue
		}
		u.AuditLog(ctx, action, "finding", id, map[string]any{"triage_status": status})
	}
}

func (u *UI) bulkAssign(r *http.Request, ids []string, userID string) {
	ctx := r.Context()
	now := time.Now().UTC().Format(time.RFC3339)
	// finding_assignment is keyed by the finding's fingerprint (one
	// assignee per fingerprint), so resolve id → fingerprint first.
	sel := `SELECT fingerprint FROM findings WHERE id = ` + ph(u.store, 1)
	ins := `INSERT INTO finding_assignment (finding_fingerprint, assignee_user_id, assigned_by_user_id, assigned_at)
	        VALUES (` + ph(u.store, 1) + `, ` + ph(u.store, 2) + `, ` + ph(u.store, 3) + `, ` + ph(u.store, 4) + `) ` +
		`ON CONFLICT (finding_fingerprint) DO UPDATE SET assignee_user_id = ` + ph(u.store, 5) +
		`, assigned_by_user_id = ` + ph(u.store, 6) + `, assigned_at = ` + ph(u.store, 7)
	for _, id := range ids {
		var fp string
		if err := u.store.DB().QueryRowContext(ctx, sel, id).Scan(&fp); err != nil {
			continue
		}
		if _, err := u.store.DB().ExecContext(ctx, ins, fp, userID, userID, now, userID, userID, now); err != nil {
			continue
		}
		u.AuditLog(ctx, "finding.assigned", "finding", id, map[string]any{"assignee_user_id": userID})
	}
}

func (u *UI) bulkWaive(r *http.Request, ids []string, userID string) {
	ctx := r.Context()
	now := time.Now().UTC().Format(time.RFC3339)
	approver := userID
	if usr, err := u.users.ByID(ctx, userID); err == nil {
		approver = usr.Email
	}
	// One waiver per finding, keyed on its check_id + resource_id.
	sel := `SELECT check_id, resource_id FROM findings WHERE id = ` + ph(u.store, 1)
	ins := `INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_by_user_id, created_at)
	        VALUES (` + phList(u.store, 7) + `)`
	for _, id := range ids {
		var checkID, resourceID string
		if err := u.store.DB().QueryRowContext(ctx, sel, id).Scan(&checkID, &resourceID); err != nil {
			continue
		}
		wid := uuid.NewString()
		if _, err := u.store.DB().ExecContext(ctx, ins,
			wid, checkID, resourceID, "Bulk-waived from the findings explorer", approver, userID, now); err != nil {
			continue
		}
		u.AuditLog(ctx, "finding.waived", "finding", id, map[string]any{"waiver_id": wid, "check_id": checkID})
	}
}

func (u *UI) bulkExportCSV(w http.ResponseWriter, r *http.Request, ids []string) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=findings-selection.csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "check_id", "severity", "status", "triage_status", "provider", "resource_name", "resource_type", "message"})
	q := `SELECT id, check_id, severity, status, triage_status, provider, resource_name, resource_type, COALESCE(message,'')
	      FROM findings WHERE id = ` + ph(u.store, 1)
	for _, id := range ids {
		var fID, checkID, sev, status, triage, provider, resName, resType, msg string
		if err := u.store.DB().QueryRowContext(ctx, q, id).Scan(
			&fID, &checkID, &sev, &status, &triage, &provider, &resName, &resType, &msg); err != nil {
			continue
		}
		_ = cw.Write([]string{fID, checkID, sev, status, triage, provider, resName, resType, msg})
	}
	u.AuditLog(ctx, "finding.exported", "finding", "", map[string]any{"count": len(ids)})
}

// findingNote updates a single finding's inline triage note + appends an
// audit_log entry. Returns the saved note as a fragment so the optimistic
// UI can reconcile.
func (u *UI) findingNote(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	if len(note) > 2000 {
		note = note[:2000]
	}
	if _, err := u.store.DB().ExecContext(r.Context(),
		`UPDATE findings SET note = `+ph(u.store, 1)+` WHERE id = `+ph(u.store, 2), note, id); err != nil {
		u.fail(w, "save note: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "finding.note_edited", "finding", id, map[string]any{"len": len(note)})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if note == "" {
		_, _ = w.Write([]byte(`<span class="text-muted-foreground italic">No note — click to add</span>`))
		return
	}
	_, _ = w.Write([]byte(template.HTMLEscapeString(note)))
}
