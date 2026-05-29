package ui

import (
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// v1.19 phase 7 — Table 2.0 column-layout persistence. table2.js loads
// a per-(user, table) layout on render + saves it (debounced) on every
// resize / reorder / pin / show-hide. The daemon treats layout_json as
// an opaque blob — the shape is owned by table2.js — but caps its size
// + validates the table id so a hostile client can't bloat the row.

var tableIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

const maxTableLayoutBytes = 16 * 1024

func (u *UI) mountTablesRoutes(r chi.Router) {
	r.Get("/tables/{id}/layout", u.getTableLayout)
	r.Post("/tables/{id}/layout", u.saveTableLayout)
}

// getTableLayout returns the saved layout JSON for (session user,
// table), or "{}" when none exists. Content-Type application/json so
// table2.js can fetch().then(r=>r.json()).
func (u *UI) getTableLayout(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	id := chi.URLParam(r, "id")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if sess == nil || !tableIDRe.MatchString(id) {
		_, _ = w.Write([]byte(`{}`))
		return
	}
	var layout string
	err := u.store.DB().QueryRowContext(r.Context(),
		`SELECT layout_json FROM user_table_state WHERE user_id = `+ph(u.store, 1)+` AND table_id = `+ph(u.store, 2),
		sess.UserID, id).Scan(&layout)
	if err != nil || layout == "" {
		_, _ = w.Write([]byte(`{}`))
		return
	}
	_, _ = w.Write([]byte(layout))
}

// saveTableLayout upserts the layout JSON for (session user, table).
// The body is the raw layout JSON (≤ maxTableLayoutBytes).
func (u *UI) saveTableLayout(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if !tableIDRe.MatchString(id) {
		http.Error(w, "invalid table id", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTableLayoutBytes+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxTableLayoutBytes {
		http.Error(w, "layout too large", http.StatusRequestEntityTooLarge)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := u.store.DB().ExecContext(r.Context(),
		`INSERT INTO user_table_state (user_id, table_id, layout_json, updated_at) VALUES (`+
			ph(u.store, 1)+`, `+ph(u.store, 2)+`, `+ph(u.store, 3)+`, `+ph(u.store, 4)+`) `+
			`ON CONFLICT (user_id, table_id) DO UPDATE SET layout_json = `+ph(u.store, 5)+`, updated_at = `+ph(u.store, 6),
		sess.UserID, id, string(body), now, string(body), now); err != nil {
		u.fail(w, "save table layout: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
