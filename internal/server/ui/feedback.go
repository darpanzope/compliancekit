package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
)

// feedbackKinds is the closed set the widget offers.
var feedbackKinds = map[string]bool{"bug": true, "feature": true, "love": true}

const feedbackMaxLen = 4000

// feedbackRow is one queue entry (admin view).
type feedbackRow struct {
	ID        string
	UserEmail string
	Kind      string
	Message   string
	PageURL   string
	Status    string
	CreatedAt string
}

type adminFeedbackView struct {
	View
	Rows []feedbackRow
}

func (u *UI) mountFeedbackRoutes(r chi.Router) {
	// Session-scoped submit (the widget posts from the logged-in UI, not
	// via an API token) — CSRF-gated by the enclosing group.
	r.Post("/feedback", u.submitFeedback)
	r.Get("/admin/feedback", u.adminOnly(u.adminFeedbackPage))
	r.Post("/admin/feedback/{id}/status", u.adminOnly(u.updateFeedbackStatus))
}

// submitFeedback validates + stores a feedback row, fires the optional
// webhook relay, and (htmx) swaps in a thank-you fragment.
func (u *UI) submitFeedback(w http.ResponseWriter, r *http.Request) {
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	kind := r.FormValue("kind")
	msg := r.FormValue("message")
	page := r.FormValue("page_url")
	if !feedbackKinds[kind] {
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}
	if msg == "" || len(msg) > feedbackMaxLen {
		http.Error(w, "message must be 1.."+strconv.Itoa(feedbackMaxLen)+" chars", http.StatusBadRequest)
		return
	}
	email := ""
	if usr, err := u.users.ByID(r.Context(), sess.UserID); err == nil {
		email = usr.Email
	}
	id := randomID()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := u.store.DB().ExecContext(r.Context(),
		`INSERT INTO feedback (id, user_id, user_email, kind, message, page_url, status, created_at) VALUES (`+
			ph(u.store, 1)+`, `+ph(u.store, 2)+`, `+ph(u.store, 3)+`, `+ph(u.store, 4)+`, `+
			ph(u.store, 5)+`, `+ph(u.store, 6)+`, 'new', `+ph(u.store, 7)+`)`,
		id, sess.UserID, email, kind, msg, page, now); err != nil {
		u.fail(w, "store feedback: "+err.Error())
		return
	}
	// Best-effort relay — never blocks or fails the submit on a webhook
	// hiccup. Reuses the v0.17 "POST a JSON envelope" convention.
	go relayFeedbackWebhook(feedbackEnvelope{Kind: kind, Message: msg, UserEmail: email, PageURL: page, CreatedAt: now})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<div class="ck-banner ck-banner-success" role="status"><div class="ck-banner-body"><p class="ck-banner-title">Thanks!</p><p class="ck-banner-message">Your note is in the queue.</p></div></div>`))
}

// adminFeedbackPage renders the triage queue (admin only).
func (u *UI) adminFeedbackPage(w http.ResponseWriter, r *http.Request) {
	rows, err := u.listFeedback(r.Context())
	if err != nil {
		u.fail(w, "list feedback: "+err.Error())
		return
	}
	u.render(w, "admin_feedback.html", adminFeedbackView{
		View: u.viewFor(r, "Feedback", "", View{}),
		Rows: rows,
	})
}

// updateFeedbackStatus moves a row through new → triaged → closed.
func (u *UI) updateFeedbackStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	status := r.FormValue("status")
	switch status {
	case "new", "triaged", "closed":
	default:
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	if _, err := u.store.DB().ExecContext(r.Context(),
		`UPDATE feedback SET status = `+ph(u.store, 1)+` WHERE id = `+ph(u.store, 2), status, id); err != nil {
		u.fail(w, "update feedback: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/feedback", http.StatusSeeOther)
}

func (u *UI) listFeedback(ctx context.Context) ([]feedbackRow, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, user_email, kind, message, page_url, status, created_at
		   FROM feedback ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []feedbackRow
	for rows.Next() {
		var f feedbackRow
		if err := rows.Scan(&f.ID, &f.UserEmail, &f.Kind, &f.Message, &f.PageURL, &f.Status, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// feedbackEnvelope is the JSON shape relayed to CK_FEEDBACK_WEBHOOK.
type feedbackEnvelope struct {
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	UserEmail string `json:"user_email"`
	PageURL   string `json:"page_url"`
	CreatedAt string `json:"created_at"`
}

// relayFeedbackWebhook POSTs the envelope to CK_FEEDBACK_WEBHOOK when
// set. Best-effort: a 5s timeout + swallowed errors so a flaky relay
// never affects the operator's submit.
func relayFeedbackWebhook(env feedbackEnvelope) {
	url := os.Getenv("CK_FEEDBACK_WEBHOOK")
	if url == "" {
		return
	}
	body, err := json.Marshal(env)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// randomID returns a 128-bit hex id for a feedback row.
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
