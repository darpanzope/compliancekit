// Package webhook handles inbound webhook receivers — GitHub PR /
// push events + operator-defined generic webhooks. Every receiver
// verifies an HMAC-SHA256 signature against either a per-source
// secret (GitHub) or a per-row secret (generic), then queues a scan
// job via the same code path as POST /api/v1/scans.
//
// The HMAC verification is constant-time. Signature format follows
// GitHub's "sha256=" + hex convention for both source types.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/events"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

const (
	// MaxBodyBytes caps inbound payloads at 1 MB. GitHub events sit
	// well under that; the limit prevents a malicious sender from
	// pinning daemon memory.
	MaxBodyBytes = 1 << 20

	// SignaturePrefix is the "sha256=" tag GitHub puts in the header
	// before the hex digest. Generic receivers use the same shape
	// for parity.
	SignaturePrefix = "sha256="
)

// Receiver is the HTTP handler bundle for both inbound paths.
type Receiver struct {
	store *store.Store

	// githubSecret is the global secret operators configure for the
	// /webhooks/github endpoint. Empty disables the route.
	githubSecret string

	// events is the optional v1.6 SSE producer. When set, every
	// accepted webhook fires a webhook.received event so dashboards
	// + toasts + the activity timeline see the request live.
	events *events.Producer
}

// Config carries the operator-controlled inbound-secrets. v1.4
// settings page wires this from the providers table; the CLI flag
// path is the v1.3 fallback.
type Config struct {
	GitHubSecret string
}

// New constructs the receiver. nil cfg is fine — both inbound paths
// will then 403 every request (no secret = no verify = no trust).
func New(st *store.Store, cfg Config) *Receiver {
	return &Receiver{store: st, githubSecret: cfg.GitHubSecret}
}

// WithEvents installs the v1.6 SSE producer so accepted webhooks
// publish webhook.received events. Returns the receiver for
// chaining.
func (rc *Receiver) WithEvents(p *events.Producer) *Receiver {
	rc.events = p
	return rc
}

// publishWebhookReceived fans out one webhook.received event to
// the bus. Safe when rc.events is nil.
func (rc *Receiver) publishWebhookReceived(source, scanID string) {
	if rc.events == nil {
		return
	}
	rc.events.Publish(events.TypeWebhookReceived, scanID, map[string]any{
		"source":  source,
		"scan_id": scanID,
	})
}

// Mount installs /webhooks/{...} routes on r. No auth middleware
// here — the routes do their own signature verification.
func (rc *Receiver) Mount(r chi.Router) {
	r.Route("/webhooks", func(r chi.Router) {
		r.Post("/github", rc.handleGitHub)
		r.Post("/{id}", rc.handleGeneric)
	})
}

// handleGitHub verifies X-Hub-Signature-256 against the operator's
// configured secret + queues a scan when the event is one of the
// recognized triggers (PR opened/synchronize, push to default
// branch). Returns 202 on accept; 401 on bad signature; 204 on a
// valid signature but ignored event type.
func (rc *Receiver) handleGitHub(w http.ResponseWriter, r *http.Request) {
	if rc.githubSecret == "" {
		http.Error(w, "github webhook receiver not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !VerifySignature(rc.githubSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	action, ok := githubScanTrigger(event, body)
	if !ok {
		w.WriteHeader(http.StatusNoContent) // valid sig, uninteresting event
		return
	}
	trigger := "github." + event + "." + action
	scanID, err := rc.enqueueScan(r.Context(), trigger, "webhook")
	if err != nil {
		http.Error(w, "enqueue: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rc.publishWebhookReceived(trigger, scanID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"scan_id":` + jsonString(scanID) + `,"trigger":` + jsonString(trigger) + `}`))
}

// handleGeneric verifies X-CK-Signature against the per-row secret
// stored in the webhooks table (looked up by the URL path component).
// On valid signature it enqueues a scan + bumps the row's received_at
// counter for audit. Disabled rows (enabled=0) return 410 Gone so the
// sender stops retrying.
func (rc *Receiver) handleGeneric(w http.ResponseWriter, r *http.Request) {
	urlPath := chi.URLParam(r, "id")
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	hook, err := rc.lookupHook(r.Context(), urlPath)
	if err != nil {
		http.Error(w, "webhook not found", http.StatusNotFound)
		return
	}
	if !hook.enabled {
		http.Error(w, "webhook disabled", http.StatusGone)
		return
	}
	if !VerifySignature(hook.secret, r.Header.Get("X-CK-Signature"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	trigger := "webhook:" + hook.id
	scanID, err := rc.enqueueScan(r.Context(), trigger, "webhook")
	if err != nil {
		http.Error(w, "enqueue: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rc.touchHook(r.Context(), hook.id)
	rc.publishWebhookReceived(trigger, scanID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"scan_id":` + jsonString(scanID) + `,"webhook":` + jsonString(hook.id) + `}`))
}

// VerifySignature is the constant-time HMAC-SHA256 check shared by
// both receivers. The header is expected as "sha256=<hex>" (GitHub
// convention); empty/malformed headers fail.
func VerifySignature(secret, header string, body []byte) bool {
	if secret == "" || header == "" {
		return false
	}
	if !strings.HasPrefix(header, SignaturePrefix) {
		return false
	}
	want, err := hex.DecodeString(header[len(SignaturePrefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// SignBody is the helper test code (and the v1.4 settings UI "test
// this webhook" button) uses to produce a valid header for a body.
func SignBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// githubScanTrigger inspects the event name + body and returns the
// action string (and true) for events worth scanning. Currently:
//
//	pull_request: opened / synchronize / reopened → scan
//	push:         only when the ref is refs/heads/main or master    → scan
//
// Anything else returns ("", false).
func githubScanTrigger(event string, body []byte) (string, bool) {
	switch event {
	case "pull_request":
		var p struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(body, &p)
		switch p.Action {
		case "opened", "synchronize", "reopened":
			return p.Action, true
		}
	case "push":
		var p struct {
			Ref string `json:"ref"`
		}
		_ = json.Unmarshal(body, &p)
		if p.Ref == "refs/heads/main" || p.Ref == "refs/heads/master" {
			return "default-branch", true
		}
	}
	return "", false
}

// genericHook is the trimmed view of one webhooks row.
type genericHook struct {
	id      string
	secret  string
	enabled bool
}

func (rc *Receiver) lookupHook(ctx context.Context, urlPath string) (*genericHook, error) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`SELECT id, secret, enabled FROM webhooks WHERE url_path = %s`,
		rc.ph(1))
	var (
		h       genericHook
		enabled int
	)
	err := rc.store.DB().QueryRowContext(ctx, q, urlPath).
		Scan(&h.id, &h.secret, &enabled)
	if err != nil {
		return nil, err
	}
	h.enabled = enabled != 0
	return &h, nil
}

func (rc *Receiver) touchHook(ctx context.Context, id string) {
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`UPDATE webhooks SET last_received_at = %s, received_count = received_count + 1 WHERE id = %s`,
		rc.ph(1), rc.ph(2))
	_, _ = rc.store.DB().ExecContext(ctx, q, time.Now().UTC().Format(time.RFC3339), id)
}

// enqueueScan inserts a row into scans with status='queued', source
// from the caller, error_message blank. Returns the new scan_id so
// the response body can echo it. v1.6 phase 9 — F21: the trigger
// string ("github.pull_request.opened" etc.) is now persisted in
// the scans.trigger column instead of being computed + discarded.
func (rc *Receiver) enqueueScan(ctx context.Context, trigger, source string) (string, error) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)
	var triggerArg any
	if trigger != "" {
		triggerArg = trigger
	}
	q := fmt.Sprintf( //nolint:gosec // placeholders only; no user input
		`INSERT INTO scans (id, created_at, source, status, providers_scanned, frameworks_scanned, trigger)
		 VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		rc.ph(1), rc.ph(2), rc.ph(3), rc.ph(4), rc.ph(5), rc.ph(6), rc.ph(7))
	_, err := rc.store.DB().ExecContext(ctx, q, id, now, source, "queued", "[]", "[]", triggerArg)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (rc *Receiver) ph(n int) string {
	if rc.store.Driver() == store.DriverPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func jsonString(s string) string {
	buf, _ := json.Marshal(s)
	return string(buf)
}

// errEmptyBody is sentinel for "no body to decode." Unused in v1.3 —
// kept here so v1.4's GitHub-event-typed handlers can compose.
var errEmptyBody = errors.New("empty body")

// Buf is the trimmed payload buffer wrapper. Used by tests +
// integration code that needs to inspect the verified body.
type Buf struct{ inner *bytes.Buffer }

func (b *Buf) Bytes() []byte  { return b.inner.Bytes() }
func (b *Buf) String() string { return b.inner.String() }
func (b *Buf) Len() int       { return b.inner.Len() }

var _ = errEmptyBody
