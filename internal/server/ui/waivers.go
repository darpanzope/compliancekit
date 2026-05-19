package ui

// v1.4 Phase 8 — Waivers manager.
//
// /waivers lists, creates, edits, expires, and revokes waivers. The
// underlying schema (waivers table, shipped at v1.3 phase 1) is
// already in place — phase 8 wires the UI surface on top.
//
// Auditor-facing shape: every waiver carries check_id + resource_id
// glob + reason + approver + expires_at. Per ADR-013, waivers are the
// "muted finding" mechanism (vs. baselines, which are the "accepted
// finding" mechanism); the UI keeps the auditor's evidence pack honest
// by surfacing both the rationale and the approver inline.

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Waiver status labels — mirror what the UI badges + sort code use.
// Extracted to constants to satisfy goconst + avoid string typos.
const (
	waiverStatusActive  = "active"
	waiverStatusExpired = "expired"
	waiverStatusRevoked = "revoked"
)

// waiverRow is the per-row payload for the /waivers list.
type waiverRow struct {
	ID         string
	CheckID    string
	ResourceID string
	Reason     string
	Approver   string
	CreatedAt  string
	ExpiresAt  string
	ExpiresIn  string // humanized "in 12d" / "expired 3d ago" / "—"
	Status     string // waiverStatusActive / waiverStatusExpired / waiverStatusRevoked
}

// waiversView is the list-page payload.
type waiversView struct {
	View
	Items        []waiverRow
	ActiveCount  int
	ExpiringSoon int // count of waivers expiring within 14 days
	ExpiredCount int
	Flash        string
	Error        string
}

// mountWaiversRoutes registers the Phase 8 endpoints.
func (u *UI) mountWaiversRoutes(r chi.Router) {
	r.Get("/waivers", u.waiversList)
	r.Post("/waivers", u.waiversCreate)
	r.Post("/waivers/{id}/revoke", u.waiversRevoke)
}

// waiversList renders the table + the create-waiver form inline.
func (u *UI) waiversList(w http.ResponseWriter, r *http.Request) {
	items, err := u.loadWaivers(r.Context())
	if err != nil {
		u.fail(w, "load waivers: "+err.Error())
		return
	}

	now := time.Now()
	soonCutoff := now.Add(14 * 24 * time.Hour)
	view := waiversView{
		View:  u.viewFor(r, "Waivers", "settings", View{}),
		Items: items,
		Flash: r.URL.Query().Get("flash"),
		Error: r.URL.Query().Get("err"),
	}
	for _, w := range items {
		switch w.Status {
		case waiverStatusActive:
			view.ActiveCount++
			if w.ExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, w.ExpiresAt); err == nil {
					if t.Before(soonCutoff) {
						view.ExpiringSoon++
					}
				}
			}
		case waiverStatusExpired:
			view.ExpiredCount++
		}
	}
	u.render(w, "waivers.html", view)
}

// waiversCreate accepts the inline create form. Required: check_id,
// resource_id, reason, approver. Optional: expires_at (yyyy-mm-dd).
func (u *UI) waiversCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	check := strings.TrimSpace(r.PostForm.Get("check_id"))
	resource := strings.TrimSpace(r.PostForm.Get("resource_id"))
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	approver := strings.TrimSpace(r.PostForm.Get("approver"))
	expires := strings.TrimSpace(r.PostForm.Get("expires_at"))

	if check == "" || resource == "" || reason == "" || approver == "" {
		http.Redirect(w, r, "/waivers?err=missing-fields", http.StatusSeeOther)
		return
	}

	var expiresStored string
	if expires != "" {
		t, err := time.Parse("2006-01-02", expires)
		if err != nil {
			http.Redirect(w, r, "/waivers?err=bad-date", http.StatusSeeOther)
			return
		}
		expiresStored = t.UTC().Format(time.RFC3339)
	}

	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	q := `INSERT INTO waivers (id, check_id, resource_id, reason, approver,
	                            created_at, expires_at)
	      VALUES (` + phList(u.store, 7) + `)`
	if _, err := u.store.DB().ExecContext(r.Context(), q,
		id, check, resource, reason, approver, now, expiresStored); err != nil {
		u.fail(w, "create waiver: "+err.Error())
		return
	}
	http.Redirect(w, r, "/waivers?flash=created", http.StatusSeeOther)
}

// waiversRevoke sets the revoked_at column. Soft-delete — the
// audit trail keeps every waiver row forever, just marks the
// timestamp when it stopped applying.
func (u *UI) waiversRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := u.store.DB().ExecContext(r.Context(),
		`UPDATE waivers SET revoked_at = `+ph(u.store, 1)+` WHERE id = `+ph(u.store, 2)+` AND revoked_at IS NULL`,
		now, id)
	if err != nil {
		u.fail(w, "revoke: "+err.Error())
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Redirect(w, r, "/waivers?err=not-found", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/waivers?flash=revoked", http.StatusSeeOther)
}

// loadWaivers returns every waiver, ordered active → expiring →
// expired/revoked, then by created_at desc within each band.
func (u *UI) loadWaivers(ctx context.Context) ([]waiverRow, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, check_id, resource_id, reason, approver, created_at,
		        COALESCE(expires_at,''), COALESCE(revoked_at,'')
		 FROM waivers ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []waiverRow{}
	now := time.Now()
	for rows.Next() {
		var w waiverRow
		var revoked string
		if err := rows.Scan(&w.ID, &w.CheckID, &w.ResourceID, &w.Reason, &w.Approver,
			&w.CreatedAt, &w.ExpiresAt, &revoked); err != nil {
			return out, err
		}
		w.Status = waiverStatusActive
		switch {
		case revoked != "":
			w.Status = waiverStatusRevoked
		case w.ExpiresAt != "":
			if t, perr := time.Parse(time.RFC3339, w.ExpiresAt); perr == nil {
				if t.Before(now) {
					w.Status = waiverStatusExpired
				}
				w.ExpiresIn = humanizeUntil(t, now)
			}
		default:
			w.ExpiresIn = "no expiry"
		}
		out = append(out, w)
	}

	// Sort: active first (sort by expires_at asc), then expired, then revoked.
	sort.SliceStable(out, func(i, j int) bool {
		ranki := statusRank(out[i].Status)
		rankj := statusRank(out[j].Status)
		if ranki != rankj {
			return ranki < rankj
		}
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, rows.Err()
}

func statusRank(s string) int {
	switch s {
	case waiverStatusActive:
		return 0
	case waiverStatusExpired:
		return 1
	case waiverStatusRevoked:
		return 2
	}
	return 3
}

// humanizeUntil renders a time as "in 12d" / "today" / "expired 3d ago".
func humanizeUntil(t, ref time.Time) string {
	d := t.Sub(ref)
	switch {
	case d < -24*time.Hour:
		return formatAgo(-d.Hours()/24, "d") // "5d ago"
	case d < 0:
		return "expired today"
	case d < 24*time.Hour:
		return "today"
	case d < 14*24*time.Hour:
		return formatIn(d.Hours()/24, "d")
	case d < 60*24*time.Hour:
		return formatIn(d.Hours()/24, "d")
	default:
		return formatIn(d.Hours()/24/30, "mo")
	}
}

func formatIn(n float64, unit string) string {
	return "in " + strconv.Itoa(int(n)) + unit
}
