package ui

// v1.5.1 phase 4 — Webhooks manager UI (F14).
//
// /settings/webhooks lists, creates, and deletes inbound webhook
// receivers. The underlying schema shipped at v1.3 phase 1 and the
// receiver handler shipped at v1.3 phase 9, but no UI ever wired
// the CRUD path — operators could only seed rows via raw SQL.
//
// Each webhook carries name + url_path (the suffix under /webhooks/)
// + secret (the HMAC signing key the sender must use) + event_types
// (JSON array — '*' by default for all events) + an enabled flag.
// The receiver lives in internal/server/webhook/webhook.go and
// verifies signatures with the stored secret on every POST.
//
// The stored secret is plaintext at-rest per v1.5.1 migration 0006
// (the v1.3 bcrypt-hash design was unusable as an HMAC key). The
// secret is shown once at creation time and never again — the table
// only renders an "edit secret" button when the operator needs to
// rotate.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// webhookRow is the per-row payload for the /settings/webhooks list.
type webhookRow struct {
	ID             string
	Name           string
	URLPath        string
	EventTypes     string
	CreatedAt      string
	LastReceivedAt string
	ReceivedCount  int
	Enabled        bool
}

// webhooksView is the list-page payload.
type webhooksView struct {
	View
	Items     []webhookRow
	NewSecret string // populated after a successful create — shown once
	Flash     string
	Error     string
	BaseURL   string // for the example curl command
}

func (u *UI) mountWebhooksRoutes(r chi.Router) {
	r.Get("/settings/webhooks", u.webhooksList)
	r.Post("/settings/webhooks", u.webhooksCreate)
	r.Post("/settings/webhooks/{id}/delete", u.webhooksDelete)
	r.Post("/settings/webhooks/{id}/toggle", u.webhooksToggle)
}

func (u *UI) webhooksList(w http.ResponseWriter, r *http.Request) {
	items, err := u.loadWebhooks(r.Context())
	if err != nil {
		u.fail(w, "load webhooks: "+err.Error())
		return
	}
	view := webhooksView{
		View:      u.viewFor(r, "Webhooks", "settings", View{}),
		Items:     items,
		NewSecret: r.URL.Query().Get("secret"),
		Flash:     r.URL.Query().Get("flash"),
		Error:     r.URL.Query().Get("err"),
		BaseURL:   webhookBaseURL(r),
	}
	u.render(w, "webhooks.html", view)
}

func (u *UI) webhooksCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	urlPath := strings.TrimSpace(r.PostForm.Get("url_path"))
	secret := strings.TrimSpace(r.PostForm.Get("secret"))
	events := strings.TrimSpace(r.PostForm.Get("event_types"))

	if name == "" || urlPath == "" {
		http.Redirect(w, r, "/settings/webhooks?err=missing-fields", http.StatusSeeOther)
		return
	}
	urlPath = strings.TrimPrefix(urlPath, "/")
	urlPath = strings.TrimPrefix(urlPath, "webhooks/")
	if urlPath == "" {
		http.Redirect(w, r, "/settings/webhooks?err=bad-path", http.StatusSeeOther)
		return
	}

	if secret == "" {
		secret = randomSecret()
	}
	if events == "" {
		events = "[]" // empty array = no filtering, all events accepted
	}

	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)

	creator := userIDFromCtx(r.Context())
	var creatorArg any
	if creator != "" {
		creatorArg = creator
	}
	q := `INSERT INTO webhooks (id, name, url_path, secret, event_types,
	                            created_by_user_id, created_at, enabled)
	      VALUES (` + phList(u.store, 8) + `)`
	if _, err := u.store.DB().ExecContext(r.Context(), q,
		id, name, urlPath, secret, events, creatorArg, now, 1); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			http.Redirect(w, r, "/settings/webhooks?err=duplicate-path", http.StatusSeeOther)
			return
		}
		u.fail(w, "insert webhook: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings/webhooks?flash=created&secret="+secret, http.StatusSeeOther)
}

func (u *UI) webhooksDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := u.store.DB().ExecContext(r.Context(),
		`DELETE FROM webhooks WHERE id = `+ph(u.store, 1), id); err != nil {
		u.fail(w, "delete webhook: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings/webhooks?flash=deleted", http.StatusSeeOther)
}

func (u *UI) webhooksToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := u.store.DB().ExecContext(r.Context(),
		`UPDATE webhooks SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END
		 WHERE id = `+ph(u.store, 1), id); err != nil {
		u.fail(w, "toggle webhook: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings/webhooks?flash=toggled", http.StatusSeeOther)
}

func (u *UI) loadWebhooks(ctx context.Context) ([]webhookRow, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT id, name, url_path, event_types, created_at,
		        COALESCE(last_received_at,''), received_count, enabled
		 FROM webhooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []webhookRow{}
	for rows.Next() {
		var (
			r       webhookRow
			enabled int
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.URLPath, &r.EventTypes,
			&r.CreatedAt, &r.LastReceivedAt, &r.ReceivedCount, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// randomSecret produces a 32-byte (64 hex char) signing secret. Used
// when the operator leaves the secret field blank on the create form.
func randomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is catastrophic; fall back to a uuid
		// (still high-entropy) rather than blocking the create.
		return strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	return hex.EncodeToString(b[:])
}

// webhookBaseURL returns the http(s)://host scheme+host the operator
// uses to register the URL with the upstream sender. Reads X-Forwarded-
// Proto/Host when set (reverse-proxy deploys) and falls back to the
// request host with the inferred scheme.
func webhookBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host
}
