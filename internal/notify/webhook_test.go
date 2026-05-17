package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

func TestWebhook_NotConfigured(t *testing.T) {
	if NewWebhook(WebhookConfig{}).Configured() {
		t.Errorf("empty config should not be Configured")
	}
}

func TestWebhook_HappyPath_NoSecret(t *testing.T) {
	var captured struct {
		body map[string]any
		sig  string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		captured.sig = r.Header.Get("X-CompliancekitSignature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := NewWebhook(WebhookConfig{
		URL:           srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{
		sampleFinding("aws-s3-public-access-block", "critical"),
	}, BuildOptions{})

	if _, err := sink.Send(context.Background(), notifications); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if captured.body["schema"] != "compliancekit.notification.v1" {
		t.Errorf("schema = %v, want v1", captured.body["schema"])
	}
	if captured.sig != "" {
		t.Errorf("no secret → no signature header expected, got %q", captured.sig)
	}
	if captured.body["fingerprint"] == nil || captured.body["fingerprint"] == "" {
		t.Errorf("fingerprint missing or empty")
	}
}

func TestWebhook_HMACSignaturePresent(t *testing.T) {
	const secret = "shared-secret-value"
	var captured struct {
		body []byte
		sig  string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.body, _ = io.ReadAll(r.Body)
		captured.sig = r.Header.Get("X-CompliancekitSignature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhook(WebhookConfig{
		URL:           srv.URL,
		Secret:        secret,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{sampleFinding("x", "critical")}, BuildOptions{})
	if _, err := sink.Send(context.Background(), notifications); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(captured.sig, "sha256=") {
		t.Fatalf("signature missing sha256= prefix: %q", captured.sig)
	}
	want := computeHMAC(secret, captured.body)
	got := strings.TrimPrefix(captured.sig, "sha256=")
	if got != want {
		t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestWebhook_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad creds"))
	}))
	defer srv.Close()

	sink := NewWebhook(WebhookConfig{
		URL:           srv.URL,
		Secret:        "x",
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{sampleFinding("x", "critical")}, BuildOptions{})
	res, _ := sink.Send(context.Background(), notifications)
	if res.Errors != 1 {
		t.Errorf("Errors = %d, want 1", res.Errors)
	}
	joined := strings.Join(res.Messages, "\n")
	if !strings.Contains(joined, "authentication failed") {
		t.Errorf("expected ErrAuth in messages: %q", joined)
	}
}

func computeHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
