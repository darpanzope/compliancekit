package ui

// v1.12 phase 5 — /settings/sessions admin surface.
//
// Lists every active (non-expired) session across the directory with
// the user, IP, user-agent fingerprint, when it was first created,
// and when it was last seen. Per-row "Revoke" deletes the session,
// which logs the target user out at next request.
//
// Admin-only — non-admins get a 403 before the handler runs.

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

func (u *UI) mountSessionsRoutes(r chi.Router) {
	r.Get("/settings/sessions", u.adminOnly(u.sessionsList))
	r.Post("/settings/sessions/{id}/revoke", u.adminOnly(u.sessionsRevoke))
}

type sessionsListView struct {
	View
	Sessions []sessionsRow
}

type sessionsRow struct {
	ID           string
	UserID       string
	UserEmail    string
	UserAgent    string
	IP           string
	CreatedAgo   string
	LastSeenAgo  string
	ExpiresAt    string
	IsCurrent    bool
	BrowserGuess string
}

func (u *UI) sessionsList(w http.ResponseWriter, r *http.Request) {
	sessions, err := u.sessions.ListAllActive(r.Context())
	if err != nil {
		u.fail(w, "list sessions: "+err.Error())
		return
	}
	current := auth.FromContext(r.Context())
	currentID := ""
	if current != nil {
		currentID = current.ID
	}
	// Resolve user emails in one round-trip via the users.All cache.
	users, err := u.users.All(r.Context())
	if err != nil {
		u.fail(w, "list users: "+err.Error())
		return
	}
	emailByID := make(map[string]string, len(users))
	for _, us := range users {
		emailByID[us.ID] = us.Email
	}
	rows := make([]sessionsRow, 0, len(sessions))
	for _, sess := range sessions {
		rows = append(rows, sessionsRow{
			ID:           sess.ID,
			UserID:       sess.UserID,
			UserEmail:    emailByID[sess.UserID],
			UserAgent:    sess.UserAgent,
			IP:           sess.IP,
			CreatedAgo:   humanizeAgo(sess.CreatedAt.UTC().Format(time.RFC3339)),
			LastSeenAgo:  humanizeAgo(sess.LastSeenAt.UTC().Format(time.RFC3339)),
			ExpiresAt:    sess.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
			IsCurrent:    sess.ID == currentID,
			BrowserGuess: guessBrowser(sess.UserAgent),
		})
	}
	view := sessionsListView{
		View:     u.viewFor(r, "Active sessions", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Sessions: rows,
	}
	u.render(w, "sessions_list.html", view)
}

func (u *UI) sessionsRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	current := auth.FromContext(r.Context())
	if current != nil && current.ID == id {
		http.Redirect(w, r, "/settings/sessions?flash=self-revoke-blocked", http.StatusSeeOther)
		return
	}
	if err := u.sessions.Destroy(r.Context(), id); err != nil {
		u.fail(w, "revoke session: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "session.revoke", "session", id, nil)
	http.Redirect(w, r, "/settings/sessions?flash=revoked", http.StatusSeeOther)
}

// guessBrowser is a tiny UA → human-string fallback so the admin
// surface shows something useful when the UA header is long. Not a
// full UA parser — just the four families operators see in practice.
func guessBrowser(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Edg/"):
		return "Chrome"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		return "Safari"
	case strings.Contains(ua, "curl/"):
		return "curl"
	case strings.HasPrefix(ua, "Go-http-client"):
		return "Go HTTP client"
	}
	return ""
}
