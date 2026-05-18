package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// WebhookConfig configures the generic webhook sink. POSTs every
// notification as JSON to the configured URL; optional HMAC-SHA256
// signing header lets the receiver verify authenticity.
//
// Payload shape (stable since v0.17.0, governed by SemVer once v1.0
// freezes the API):
//
//	{
//	  "schema":      "compliancekit.notification.v1",
//	  "fingerprint": "abc123...",
//	  "title":       "[CRITICAL] aws-s3-public-access-block on prod",
//	  "body":        "<CommonMark>",
//	  "url":         "https://...",
//	  "tags":        ["s3", "data-exposure"],
//	  "finding":     { ...compliancekit.Finding... }
//	}
//
// When Secret is set, the request includes an X-CompliancekitSignature
// header: `sha256=<hex(HMAC-SHA256(secret, body))>`. Same format
// GitHub webhook receivers expect; receiver code reused across hooks.
//
// Env: COMPLIANCEKIT_WEBHOOK_URL, COMPLIANCEKIT_WEBHOOK_SECRET,
// COMPLIANCEKIT_WEBHOOK_THRESHOLD.
type WebhookConfig struct {
	URL           string
	Secret        string
	SeverityFloor compliancekit.Severity
	HTTPClient    *http.Client
}

// Webhook implements Notifier for generic HTTP POST sinks.
type Webhook struct{ cfg WebhookConfig }

// NewWebhook constructs a Webhook sink.
func NewWebhook(cfg WebhookConfig) *Webhook { return &Webhook{cfg: cfg} }

// Name implements Notifier.
func (w *Webhook) Name() string { return "webhook" }

// Configured returns true when URL is set.
func (w *Webhook) Configured() bool { return w.cfg.URL != "" }

// Threshold returns the per-sink severity floor.
func (w *Webhook) Threshold() compliancekit.Severity { return w.cfg.SeverityFloor }

// Send dispatches the notifications. One POST per notification (not
// a batch) so the receiver can correlate request ↔ finding without
// having to parse a list.
func (w *Webhook) Send(ctx context.Context, notifications []Notification) (Result, error) {
	var res Result
	for _, n := range notifications {
		if err := w.sendOne(ctx, n); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("webhook: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("webhook: %s — sent", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("webhook: all %d sends failed", res.Errors)
	}
	return res, nil
}

func (w *Webhook) sendOne(ctx context.Context, n Notification) error {
	payload := map[string]any{
		"schema":      "compliancekit.notification.v1",
		"fingerprint": n.Fingerprint,
		"title":       n.Title,
		"body":        n.Body,
		"finding":     n.Finding,
	}
	if n.URL != "" {
		payload["url"] = n.URL
	}
	if len(n.Tags) > 0 {
		payload["tags"] = n.Tags
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	client := w.cfg.HTTPClient
	if client == nil {
		client = HTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "compliancekit/1.0")
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(raw)
		req.Header.Set("X-CompliancekitSignature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrAuth, string(respBody))
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
}

func init() {
	cfg := WebhookConfig{
		URL:    os.Getenv("COMPLIANCEKIT_WEBHOOK_URL"),
		Secret: os.Getenv("COMPLIANCEKIT_WEBHOOK_SECRET"),
	}
	if t := os.Getenv("COMPLIANCEKIT_WEBHOOK_THRESHOLD"); t != "" {
		if sev, err := compliancekit.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewWebhook(cfg))
}
