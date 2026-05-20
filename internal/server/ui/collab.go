package ui

// v1.8 phase 2 — Assignees on findings + owners on resources.
//
// The detail panel's overview tab grows two new picker rows:
//   • "Assigned to <name> [change]" / "Unassigned [assign]"
//   • "Resource owner <name> [change]"
// Each one POSTs back to a small endpoint mounted here that upserts
// the corresponding row in finding_assignment / resource_owner.
//
// A new sidebar entry "Assigned to me" lands in nav and lists every
// finding currently assigned to the operator (joined back to the
// findings table by fingerprint).

import (
	"context"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/collab"
)

// pickerOption is one option in an assignee/owner select widget.
type pickerOption struct {
	ID    string
	Label string
}

// mountCollabRoutes wires the v1.8 phase 2 assignment + ownership
// endpoints under the RequireAuth + RequireCSRF group.
func (u *UI) mountCollabRoutes(r chi.Router) {
	r.Post("/findings/{id}/assign", u.findingAssign)
	r.Post("/findings/{id}/unassign", u.findingUnassign)
	r.Post("/resources/{id}/owner", u.resourceOwnerSet)
	r.Post("/resources/{id}/owner/clear", u.resourceOwnerClear)
}

// findingAssign upserts the assignee for the finding's fingerprint.
// body field `user_id` may be empty → unassign (alias of /unassign).
func (u *UI) findingAssign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	assigneeID := r.FormValue("user_id")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if assigneeID == "" {
		_ = u.assignments().Unset(r.Context(), row.Fingerprint)
		u.AuditLog(r.Context(), "finding.unassign", "finding", row.ID, map[string]any{
			"fingerprint": row.Fingerprint,
		})
		u.renderAssigneeWidget(w, r, row)
		return
	}
	if _, err := u.assignments().Set(r.Context(), row.Fingerprint, assigneeID, sess.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "finding.assign", "finding", row.ID, map[string]any{
		"fingerprint": row.Fingerprint,
		"assignee_id": assigneeID,
	})
	u.renderAssigneeWidget(w, r, row)
}

// findingUnassign is the explicit unassign route — same handler as
// findingAssign with no user_id, exposed for clarity.
func (u *UI) findingUnassign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := u.loadFindingByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// sql.ErrNoRows is fine — operator clicked unassign on an
	// already-unassigned row. Any other error is silently absorbed so
	// the widget refresh below still happens.
	_ = u.assignments().Unset(r.Context(), row.Fingerprint)
	u.AuditLog(r.Context(), "finding.unassign", "finding", row.ID, map[string]any{
		"fingerprint": row.Fingerprint,
	})
	u.renderAssigneeWidget(w, r, row)
}

// renderAssigneeWidget refreshes the assignee chip on the detail
// panel after a mutation. Pulls the latest row + the picker option
// list so the operator can swap in another assignee without a
// full-tab reload.
func (u *UI) renderAssigneeWidget(w http.ResponseWriter, r *http.Request, row findingRow) {
	current, _ := u.assignments().Get(r.Context(), row.Fingerprint)
	options := u.pickerOptions(r.Context())
	sess := auth.FromContext(r.Context())
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	u.renderPartial(w, "assignee_widget", struct {
		FindingID string
		Current   collab.Assignment
		Options   []pickerOption
		CSRFToken string
	}{
		FindingID: row.ID,
		Current:   current,
		Options:   options,
		CSRFToken: csrf,
	})
}

// resourceOwnerSet upserts the owner for the resource.
func (u *UI) resourceOwnerSet(w http.ResponseWriter, r *http.Request) {
	resID := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	ownerID := r.FormValue("user_id")
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if ownerID == "" {
		_ = u.owners().Unset(r.Context(), resID)
		u.AuditLog(r.Context(), "resource.owner_cleared", "resource", resID, nil)
	} else {
		if _, err := u.owners().Set(r.Context(), resID, ownerID, sess.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		u.AuditLog(r.Context(), "resource.owner_set", "resource", resID, map[string]any{
			"owner_id": ownerID,
		})
	}
	u.renderOwnerWidget(w, r, resID)
}

// resourceOwnerClear is the dedicated clear-owner route.
func (u *UI) resourceOwnerClear(w http.ResponseWriter, r *http.Request) {
	resID := chi.URLParam(r, "id")
	_ = u.owners().Unset(r.Context(), resID)
	u.AuditLog(r.Context(), "resource.owner_cleared", "resource", resID, nil)
	u.renderOwnerWidget(w, r, resID)
}

// renderOwnerWidget refreshes the resource owner chip.
func (u *UI) renderOwnerWidget(w http.ResponseWriter, r *http.Request, resourceID string) {
	current, _ := u.owners().Get(r.Context(), resourceID)
	options := u.pickerOptions(r.Context())
	sess := auth.FromContext(r.Context())
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	u.renderPartial(w, "owner_widget", struct {
		ResourceID string
		Current    collab.ResourceOwner
		Options    []pickerOption
		CSRFToken  string
	}{
		ResourceID: resourceID,
		Current:    current,
		Options:    options,
		CSRFToken:  csrf,
	})
}

// pickerOptions loads every user in the directory + projects to
// the picker option shape. Sort by Label client-readable order.
func (u *UI) pickerOptions(ctx context.Context) []pickerOption {
	users, err := u.users.All(ctx)
	if err != nil {
		return nil
	}
	out := make([]pickerOption, 0, len(users))
	for _, us := range users {
		label := us.DisplayName
		if label == "" {
			label = us.Email
		}
		out = append(out, pickerOption{ID: us.ID, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// assignments returns the Assignments handle, lazily constructed.
func (u *UI) assignments() *collab.Assignments {
	if u.assignmentsRepo == nil {
		u.assignmentsRepo = collab.NewAssignments(u.store)
	}
	return u.assignmentsRepo
}

// owners returns the Owners handle, lazily constructed.
func (u *UI) owners() *collab.Owners {
	if u.ownersRepo == nil {
		u.ownersRepo = collab.NewOwners(u.store)
	}
	return u.ownersRepo
}
