package ui

// v1.5 Phase 2 — Saved filter views for the findings explorer.
//
// Routes:
//
//	GET  /findings/views                 list saved views
//	POST /findings/views                 create from current filters
//	POST /findings/views/{id}/pin        toggle pinned state
//	POST /findings/views/{id}/delete     delete
//
// Each saved view is a (name, query_string, pinned, owner_user_id)
// row. The query_string is everything after the `?` in /findings —
// reloading the view just reuses the existing explorer route with
// the stored query, so saved views inherit any future filter
// dimensions automatically.
//
// Pinned views render in the sidebar under "Findings" (loaded by
// the chrome render path at every page render).

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// savedView is the per-row payload.
type savedView struct {
	ID          string
	Name        string
	QueryString string
	Pinned      bool
	CreatedAt   string
	CreatedIn   string
	OwnerUserID string
	IsMine      bool
}

type savedViewsView struct {
	View
	Items []savedView
	Flash string
	Error string
}

// mountSavedViewRoutes registers the Phase 2 endpoints.
func (u *UI) mountSavedViewRoutes(r chi.Router) {
	r.Get("/findings/views", u.savedViewsList)
	r.Post("/findings/views", u.savedViewsCreate)
	r.Post("/findings/views/{id}/pin", u.savedViewsPin)
	r.Post("/findings/views/{id}/delete", u.savedViewsDelete)
}

func (u *UI) savedViewsList(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	items, err := u.loadSavedViews(r.Context(), userID)
	if err != nil {
		u.fail(w, "load views: "+err.Error())
		return
	}
	view := savedViewsView{
		View:  u.viewFor(r, "Saved views · Findings", "findings", View{}),
		Items: items,
		Flash: r.URL.Query().Get("flash"),
		Error: r.URL.Query().Get("err"),
	}
	u.render(w, "saved_views.html", view)
}

// savedViewsCreate accepts a name + a query string and writes the
// row. The query string can be passed explicitly (when the operator
// is saving from a custom filter set) or copied from the current
// Referer URL when empty.
func (u *UI) savedViewsCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	query := strings.TrimSpace(r.PostForm.Get("query_string"))
	if query == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if i := strings.Index(ref, "?"); i >= 0 {
				query = ref[i+1:]
			}
		}
	}
	if name == "" {
		http.Redirect(w, r, "/findings/views?err=missing-name", http.StatusSeeOther)
		return
	}
	pinned := r.PostForm.Get("pinned") == "1"
	pinnedVal := 0
	if pinned {
		pinnedVal = 1
	}

	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	userID := userIDFromCtx(r.Context())

	// v1.5.1 F10: "Share with team" makes the view visible to every
	// user via owner_user_id NULL. Schema supported this from v1.5;
	// the create form just never exposed the checkbox + the handler
	// always defaulted ownerArg to the session user. Admin-gated to
	// prevent any logged-in user from broadcasting noisy views.
	teamShare := r.PostForm.Get("team") == "1"
	var ownerArg any
	if teamShare && u.isAdmin(r.Context()) {
		ownerArg = nil // team-wide
	} else if userID != "" {
		ownerArg = userID
	}

	q := `INSERT INTO saved_views (id, owner_user_id, created_at, name, query_string, pinned)
	      VALUES (` + phList(u.store, 6) + `)`
	if _, err := u.store.DB().ExecContext(r.Context(), q,
		id, ownerArg, now, name, query, pinnedVal); err != nil {
		u.fail(w, "create view: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "saved_view.create", "saved_view", id, map[string]any{
		"name": name, "pinned": pinned, "team_wide": ownerArg == nil,
	})
	http.Redirect(w, r, "/findings/views?flash=created", http.StatusSeeOther)
}

// isAdmin returns true when the session-attached user has IsAdmin
// set. Returns false on missing session or DB error — defensive
// default for write-side gates (F10 + future admin-only paths).
func (u *UI) isAdmin(ctx context.Context) bool {
	sess := auth.FromContext(ctx)
	if sess == nil || sess.UserID == "" {
		return false
	}
	user, err := u.users.ByID(ctx, sess.UserID)
	if err != nil || user == nil {
		return false
	}
	return user.IsAdmin
}

func (u *UI) savedViewsPin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Flip the pinned flag.
	_, err := u.store.DB().ExecContext(r.Context(),
		`UPDATE saved_views SET pinned = (CASE pinned WHEN 1 THEN 0 ELSE 1 END) WHERE id = `+ph(u.store, 1),
		id)
	if err != nil {
		u.fail(w, "pin: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "saved_view.pin_toggle", "saved_view", id, nil)
	http.Redirect(w, r, "/findings/views?flash=pinned", http.StatusSeeOther)
}

func (u *UI) savedViewsDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := u.store.DB().ExecContext(r.Context(),
		`DELETE FROM saved_views WHERE id = `+ph(u.store, 1), id)
	if err != nil {
		u.fail(w, "delete: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "saved_view.delete", "saved_view", id, nil)
	http.Redirect(w, r, "/findings/views?flash=deleted", http.StatusSeeOther)
}

// loadSavedViews returns every view visible to userID — their own
// + team-wide views (owner_user_id NULL).
func (u *UI) loadSavedViews(ctx context.Context, userID string) ([]savedView, error) {
	q := `SELECT id, COALESCE(owner_user_id,''), created_at, name, COALESCE(query_string,''), pinned
	      FROM saved_views`
	args := []any{}
	if userID != "" {
		q += ` WHERE owner_user_id = ` + ph(u.store, 1) + ` OR owner_user_id IS NULL`
		args = append(args, userID)
	} else {
		q += ` WHERE owner_user_id IS NULL`
	}
	q += ` ORDER BY pinned DESC, name ASC`

	rows, err := u.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []savedView{}
	for rows.Next() {
		var v savedView
		var pinned int
		if err := rows.Scan(&v.ID, &v.OwnerUserID, &v.CreatedAt, &v.Name, &v.QueryString, &pinned); err != nil {
			return out, err
		}
		v.Pinned = pinned != 0
		v.IsMine = userID != "" && v.OwnerUserID == userID
		v.CreatedIn = humanizeAgo(v.CreatedAt)
		out = append(out, v)
	}
	return out, rows.Err()
}

// pinnedSavedViews returns just the views the chrome renders in the
// sidebar (pinned only, scoped to the user + team-wide). Loaded by
// the topbar render path on every page; failures swallowed so a
// flaky table can't take the chrome down.
func (u *UI) pinnedSavedViews(ctx context.Context, userID string) []savedView {
	q := `SELECT id, name, COALESCE(query_string,'') FROM saved_views WHERE pinned = 1`
	args := []any{}
	if userID != "" {
		q += ` AND (owner_user_id = ` + ph(u.store, 1) + ` OR owner_user_id IS NULL)`
		args = append(args, userID)
	} else {
		q += ` AND owner_user_id IS NULL`
	}
	q += ` ORDER BY name ASC LIMIT 8`

	rows, err := u.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := []savedView{}
	for rows.Next() {
		var v savedView
		if err := rows.Scan(&v.ID, &v.Name, &v.QueryString); err != nil {
			return out
		}
		out = append(out, v)
	}
	return out
}

// userIDFromCtx returns the logged-in user's ID or "" if no session
// is in scope. Convenience over the raw auth.FromContext check.
func userIDFromCtx(ctx context.Context) string {
	if sess := auth.FromContext(ctx); sess != nil {
		return sess.UserID
	}
	return ""
}
