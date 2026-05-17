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

func TestDiscord_NotConfigured(t *testing.T) {
	if NewDiscord(DiscordConfig{}).Configured() {
		t.Errorf("empty config should not be Configured")
	}
}

func TestDiscord_HappyPath(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink := NewDiscord(DiscordConfig{
		WebhookURL:    srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{
		sampleFinding("aws-s3-public-access-block", "critical"),
	}, BuildOptions{URLPrefix: "https://x"})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("Sent = %d", res.Sent)
	}
	embeds, _ := captured["embeds"].([]any)
	if len(embeds) != 1 {
		t.Fatalf("expected 1 embed; got %d", len(embeds))
	}
	first, _ := embeds[0].(map[string]any)
	if first["color"] != float64(0xD7263D) {
		t.Errorf("color = %v, want critical red", first["color"])
	}
	if !strings.Contains(first["title"].(string), "aws-s3-public-access-block") {
		t.Errorf("title missing CheckID: %v", first["title"])
	}
}

func TestDiscord_AllSendsFailReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	sink := NewDiscord(DiscordConfig{
		WebhookURL:    srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{sampleFinding("x", "critical")}, BuildOptions{})
	_, err := sink.Send(context.Background(), notifications)
	if err == nil {
		t.Fatalf("expected error on all-fail")
	}
}
