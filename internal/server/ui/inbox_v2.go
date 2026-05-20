package ui

// v1.8 phase 9 — Notification inbox 2.0 + email digest builder.
//
// Layers four ergonomic affordances onto the v1.4 inbox:
//   • Snooze: hide a row until snoozed_until passes; "1h", "4h",
//     "tomorrow", "next week" presets surface in the row chrome.
//   • Mute thread: silence every future row sharing muted_thread_id.
//   • Event-type filter: ?type=alert|comment|mention|digest.
//   • Per-user prefs page at /inbox/prefs — DND window, digest cadence,
//     per-event-type routing (inbox / email / silent).
//
// The email-digest builder renders a Markdown summary that the v0.17
// email sink can mail out. This phase ships the builder + the
// /inbox/prefs CRUD; the cron scheduler that actually delivers the
// digest is the next slot (deferred to v1.8.x).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

// inboxPrefs is the per-user notification preference shape mirrored
// onto inbox_prefs.
type inboxPrefs struct {
	UserID        string
	Timezone      string
	DNDStart      string // "HH:MM" or ""
	DNDEnd        string
	DigestDaily   bool
	DigestWeekly  bool
	DigestHour    int
	DigestWeekday int // 0=Sun .. 6=Sat
	Routing       map[string]string
	UpdatedAt     time.Time
}

// mountInboxV2Routes wires the v1.8 phase 9 surface.
func (u *UI) mountInboxV2Routes(r chi.Router) {
	r.Post("/inbox/{id}/snooze", u.inboxSnooze)
	r.Post("/inbox/{id}/mute", u.inboxMute)
	r.Get("/inbox/prefs", u.inboxPrefsPage)
	r.Post("/inbox/prefs", u.inboxPrefsSave)
	r.Get("/inbox/digest/preview", u.inboxDigestPreview)
}

// inboxSnooze sets snoozed_until on the row. The `for` form field is
// one of: "1h", "4h", "tomorrow", "next_week".
func (u *UI) inboxSnooze(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	delta := resolveSnooze(r.FormValue("for"))
	if delta == 0 {
		http.Error(w, "invalid snooze duration", http.StatusBadRequest)
		return
	}
	until := time.Now().Add(delta).UTC().Format(time.RFC3339)
	_, _ = u.store.DB().ExecContext(r.Context(),
		`UPDATE inbox SET snoozed_until = `+ph(u.store, 1)+` WHERE id = `+ph(u.store, 2),
		until, id)
	u.AuditLog(r.Context(), "inbox.snooze", "inbox", id, map[string]any{"until": until})
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// inboxMute sets muted_thread_id on the row + every row sharing the
// same href (heuristic: same finding href = same conversation).
func (u *UI) inboxMute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	// Look up href to use as the mute key. We deliberately don't add
	// a dedicated thread_id column to inbox; the href IS the thread.
	var href string
	_ = u.store.DB().QueryRowContext(r.Context(),
		`SELECT COALESCE(href,'') FROM inbox WHERE id = `+ph(u.store, 1), id).Scan(&href)
	if href == "" {
		http.Error(w, "row has no href to mute", http.StatusBadRequest)
		return
	}
	_, _ = u.store.DB().ExecContext(r.Context(),
		`UPDATE inbox SET muted_thread_id = `+ph(u.store, 1)+` WHERE href = `+ph(u.store, 2),
		href, href)
	u.AuditLog(r.Context(), "inbox.mute", "inbox", id, map[string]any{"href": href})
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// inboxPrefsPage renders /inbox/prefs.
func (u *UI) inboxPrefsPage(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	prefs := u.loadInboxPrefs(r.Context(), sess.UserID)
	view := struct {
		View
		Prefs inboxPrefs
	}{
		View:  u.viewFor(r, "Inbox preferences", "inbox", View{}),
		Prefs: prefs,
	}
	u.render(w, "inbox_prefs.html", view)
}

// inboxPrefsSave upserts the row from the form.
func (u *UI) inboxPrefsSave(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	prefs := inboxPrefs{
		UserID:   sess.UserID,
		Timezone: r.FormValue("timezone"),
		DNDStart: r.FormValue("dnd_start"),
		DNDEnd:   r.FormValue("dnd_end"),
		Routing: map[string]string{
			"alert":   r.FormValue("route_alert"),
			"comment": r.FormValue("route_comment"),
			"mention": r.FormValue("route_mention"),
			"digest":  r.FormValue("route_digest"),
		},
	}
	prefs.DigestDaily = r.FormValue("digest_daily") == "on"
	prefs.DigestWeekly = r.FormValue("digest_weekly") == "on"
	if h, err := strconv.Atoi(r.FormValue("digest_hour")); err == nil {
		prefs.DigestHour = clamp(h, 0, 23)
	}
	if d, err := strconv.Atoi(r.FormValue("digest_weekday")); err == nil {
		prefs.DigestWeekday = clamp(d, 0, 6)
	}
	if prefs.Timezone == "" {
		prefs.Timezone = "UTC"
	}
	u.saveInboxPrefs(r.Context(), prefs)
	u.AuditLog(r.Context(), "inbox.prefs_update", "inbox_prefs", sess.UserID, nil)
	http.Redirect(w, r, "/inbox/prefs?flash=saved", http.StatusSeeOther)
}

// inboxDigestPreview renders the markdown email body the digest job
// would send right now for the session user. Useful both for the
// /inbox/prefs page preview pane + as the input to the v0.17 email
// sink when the cron job fires.
func (u *UI) inboxDigestPreview(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	md := u.buildDigest(r.Context(), sess.UserID, 24*time.Hour)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(md))
}

// ─── internals ─────────────────────────────────────────────────────────

// resolveSnooze maps preset names to a duration.
func resolveSnooze(key string) time.Duration {
	switch key {
	case "1h":
		return time.Hour
	case "4h":
		return 4 * time.Hour
	case "tomorrow":
		return 24 * time.Hour
	case "next_week":
		return 7 * 24 * time.Hour
	}
	return 0
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// loadInboxPrefs returns the per-user prefs row, defaults applied
// when none exists yet.
func (u *UI) loadInboxPrefs(ctx context.Context, userID string) inboxPrefs {
	prefs := inboxPrefs{
		UserID:        userID,
		Timezone:      "UTC",
		DigestDaily:   false,
		DigestWeekly:  false,
		DigestHour:    9,
		DigestWeekday: 1,
		Routing: map[string]string{
			"alert": "email", "comment": "inbox", "mention": "email", "digest": "email",
		},
	}
	var (
		tz, dndStart, dndEnd, routingJSON string
		dailyN, weeklyN, hour, weekday    int
	)
	row := u.store.DB().QueryRowContext(ctx,
		`SELECT timezone, COALESCE(dnd_start,''), COALESCE(dnd_end,''),
		        digest_daily, digest_weekly, digest_hour, digest_weekday, routing_json
		 FROM inbox_prefs WHERE user_id = `+ph(u.store, 1), userID)
	if err := row.Scan(&tz, &dndStart, &dndEnd, &dailyN, &weeklyN, &hour, &weekday, &routingJSON); err != nil {
		return prefs
	}
	prefs.Timezone = tz
	prefs.DNDStart = dndStart
	prefs.DNDEnd = dndEnd
	prefs.DigestDaily = dailyN != 0
	prefs.DigestWeekly = weeklyN != 0
	prefs.DigestHour = hour
	prefs.DigestWeekday = weekday
	if routingJSON != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(routingJSON), &m); err == nil && len(m) > 0 {
			prefs.Routing = m
		}
	}
	return prefs
}

func (u *UI) saveInboxPrefs(ctx context.Context, p inboxPrefs) {
	routingJSON, _ := json.Marshal(p.Routing)
	now := time.Now().UTC().Format(time.RFC3339)
	daily, weekly := 0, 0
	if p.DigestDaily {
		daily = 1
	}
	if p.DigestWeekly {
		weekly = 1
	}
	var dndStart, dndEnd any
	if p.DNDStart != "" {
		dndStart = p.DNDStart
	}
	if p.DNDEnd != "" {
		dndEnd = p.DNDEnd
	}
	q := u.upsertInboxPrefsSQL()
	_, _ = u.store.DB().ExecContext(ctx, q,
		p.UserID, p.Timezone, dndStart, dndEnd, daily, weekly,
		p.DigestHour, p.DigestWeekday, string(routingJSON), now)
}

// upsertInboxPrefsSQL returns the per-driver upsert string. The DO
// UPDATE clause does NOT include the user_id (the conflict key).
func (u *UI) upsertInboxPrefsSQL() string {
	if u.store.Driver() == store.DriverPostgres {
		return `INSERT INTO inbox_prefs (user_id, timezone, dnd_start, dnd_end,
		                                 digest_daily, digest_weekly, digest_hour, digest_weekday,
		                                 routing_json, updated_at)
		        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		        ON CONFLICT (user_id) DO UPDATE SET
		          timezone = EXCLUDED.timezone,
		          dnd_start = EXCLUDED.dnd_start,
		          dnd_end = EXCLUDED.dnd_end,
		          digest_daily = EXCLUDED.digest_daily,
		          digest_weekly = EXCLUDED.digest_weekly,
		          digest_hour = EXCLUDED.digest_hour,
		          digest_weekday = EXCLUDED.digest_weekday,
		          routing_json = EXCLUDED.routing_json,
		          updated_at = EXCLUDED.updated_at`
	}
	return `INSERT INTO inbox_prefs (user_id, timezone, dnd_start, dnd_end,
	                                 digest_daily, digest_weekly, digest_hour, digest_weekday,
	                                 routing_json, updated_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (user_id) DO UPDATE SET
	          timezone = excluded.timezone,
	          dnd_start = excluded.dnd_start,
	          dnd_end = excluded.dnd_end,
	          digest_daily = excluded.digest_daily,
	          digest_weekly = excluded.digest_weekly,
	          digest_hour = excluded.digest_hour,
	          digest_weekday = excluded.digest_weekday,
	          routing_json = excluded.routing_json,
	          updated_at = excluded.updated_at`
}

// buildDigest renders the digest body for one user covering the
// given window. Markdown so the v0.17 email sink can convert it.
func (u *UI) buildDigest(ctx context.Context, userID string, window time.Duration) string {
	since := time.Now().Add(-window).UTC().Format(time.RFC3339)
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT severity, title, body, COALESCE(href,''), event_type
		 FROM inbox
		 WHERE created_at >= `+ph(u.store, 1)+
			` AND (user_id = `+ph(u.store, 2)+` OR user_id IS NULL)
		   AND muted_thread_id IS NULL
		 ORDER BY created_at DESC LIMIT 50`, since, userID)
	if err != nil {
		return "_Digest unavailable: " + err.Error() + "_"
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	b.WriteString("# Compliancekit digest\n\n")
	b.WriteString(fmt.Sprintf("Window: last %s\n\n", window))
	count := 0
	for rows.Next() {
		var sev, title, body, href, eventType string
		if err := rows.Scan(&sev, &title, &body, &href, &eventType); err != nil {
			continue
		}
		count++
		fmt.Fprintf(&b, "## [%s] %s\n", strings.ToUpper(sev), title)
		if body != "" {
			b.WriteString(body)
			b.WriteString("\n")
		}
		if href != "" {
			fmt.Fprintf(&b, "→ %s\n\n", href)
		} else {
			b.WriteString("\n")
		}
	}
	if count == 0 {
		return "# Compliancekit digest\n\nAll quiet — no new alerts in the last " + window.String() + ".\n"
	}
	return b.String()
}
