package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

func TestSlack_NotConfigured(t *testing.T) {
	if NewSlack(SlackConfig{}).Configured() {
		t.Errorf("empty config should not be Configured")
	}
	if !NewSlack(SlackConfig{WebhookURL: "https://hooks.slack.com/x"}).Configured() {
		t.Errorf("webhook URL alone should be Configured")
	}
	if !NewSlack(SlackConfig{BotToken: "xoxb-foo", Channel: "#x"}).Configured() {
		t.Errorf("bot token + channel should be Configured")
	}
	if NewSlack(SlackConfig{BotToken: "xoxb-foo"}).Configured() {
		t.Errorf("bot token without channel should NOT be Configured")
	}
}

func TestSlack_WebhookHappyPath(t *testing.T) {
	var captured struct {
		path string
		body map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sink := NewSlack(SlackConfig{
		WebhookURL:    srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{
		sampleFinding("aws-s3-public-access-block", "critical"),
	}, BuildOptions{URLPrefix: "https://x.example.com"})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 1 || res.Errors != 0 {
		t.Errorf("Result: %+v", res)
	}
	// Sanity-check the payload shape.
	if captured.body["text"] == nil {
		t.Errorf("missing text fallback")
	}
	blocks, _ := captured.body["blocks"].([]any)
	if len(blocks) != 3 {
		t.Errorf("expected 3 blocks (section + section + actions), got %d", len(blocks))
	}
	first, _ := blocks[0].(map[string]any)
	text, _ := first["text"].(map[string]any)
	textVal, _ := text["text"].(string)
	if !strings.Contains(textVal, "rotating_light") || !strings.Contains(textVal, "aws-s3-public-access-block") {
		t.Errorf("first block missing emoji or CheckID: %q", textVal)
	}
}

func TestSlack_BotTokenIncludesChannelAndAuth(t *testing.T) {
	var captured struct {
		auth string
		body map[string]any
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": true, "ts": "1234.5678"}`))
	}))
	defer srv.Close()

	// Bot-token path hardcodes the Slack API URL — rewrite via transport.
	sink := NewSlack(SlackConfig{
		BotToken:      "xoxb-test-secret",
		Channel:       "#security",
		SeverityFloor: core.SeverityInfo,
		HTTPClient: &http.Client{
			Transport: redirectAll(srv.URL, srv.Client().Transport),
		},
	})
	notifications := BuildNotifications([]core.Finding{
		sampleFinding("aws-iam-root-mfa", "critical"),
	}, BuildOptions{})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("Sent = %d, want 1", res.Sent)
	}
	if captured.auth != "Bearer xoxb-test-secret" {
		t.Errorf("auth header = %q", captured.auth)
	}
	if captured.body["channel"] != "#security" {
		t.Errorf("channel = %v, want #security", captured.body["channel"])
	}
}

func TestSlack_APIErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": false, "error": "invalid_payload"}`))
	}))
	defer srv.Close()

	sink := NewSlack(SlackConfig{
		BotToken:      "xoxb-test",
		Channel:       "#x",
		SeverityFloor: core.SeverityInfo,
		HTTPClient: &http.Client{
			Transport: redirectAll(srv.URL, srv.Client().Transport),
		},
	})
	notifications := BuildNotifications([]core.Finding{sampleFinding("x", "critical")}, BuildOptions{})

	res, err := sink.Send(context.Background(), notifications)
	if err == nil {
		t.Fatalf("expected error when all sends fail; got nil")
	}
	if res.Errors != 1 {
		t.Errorf("Errors = %d, want 1", res.Errors)
	}
	if !strings.Contains(err.Error(), "all 1 sends failed") {
		t.Errorf("error message: %v", err)
	}
}

func TestSlack_AuthFailureReturnsErrAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_auth"}`))
	}))
	defer srv.Close()

	sink := NewSlack(SlackConfig{
		WebhookURL:    srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{sampleFinding("x", "critical")}, BuildOptions{})

	res, _ := sink.Send(context.Background(), notifications)
	if res.Errors != 1 {
		t.Errorf("Errors = %d, want 1", res.Errors)
	}
	// The error is per-notification; the top-level Send doesn't
	// propagate it but logs into Messages.
	joined := strings.Join(res.Messages, "\n")
	if !strings.Contains(joined, "authentication failed") {
		t.Errorf("expected ErrAuth in messages: %q", joined)
	}
}

// redirectAll rewrites every outbound request to point at target,
// preserving headers + body. Used to hijack the Slack API URL
// inside tests without changing the production code path.
func redirectAll(target string, base http.RoundTripper) http.RoundTripper {
	return &redirectAllTransport{target: target, base: base}
}

type redirectAllTransport struct {
	target string
	base   http.RoundTripper
}

func (r *redirectAllTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rewritten := r.target + req.URL.Path
	req2, err := http.NewRequestWithContext(req.Context(), req.Method, rewritten, req.Body)
	if err != nil {
		return nil, err
	}
	req2.Header = req.Header.Clone()
	return r.base.RoundTrip(req2)
}
