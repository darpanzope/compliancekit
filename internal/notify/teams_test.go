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

func TestTeams_NotConfigured(t *testing.T) {
	if NewTeams(TeamsConfig{}).Configured() {
		t.Errorf("empty config should not be Configured")
	}
}

func TestTeams_MessageCardShape(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewTeams(TeamsConfig{
		WebhookURL:    srv.URL,
		SeverityFloor: core.SeverityInfo,
		HTTPClient:    srv.Client(),
	})
	notifications := BuildNotifications([]core.Finding{
		sampleFinding("aws-iam-root-mfa", "critical"),
	}, BuildOptions{URLPrefix: "https://x"})

	if _, err := sink.Send(context.Background(), notifications); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if captured["@type"] != "MessageCard" {
		t.Errorf("@type = %v, want MessageCard", captured["@type"])
	}
	if captured["themeColor"] != "D7263D" {
		t.Errorf("themeColor = %v, want critical hex", captured["themeColor"])
	}
	sections, _ := captured["sections"].([]any)
	if len(sections) != 1 {
		t.Fatalf("expected 1 section; got %d", len(sections))
	}
	first, _ := sections[0].(map[string]any)
	if !strings.Contains(first["activityTitle"].(string), "critical") {
		t.Errorf("activityTitle missing severity: %v", first["activityTitle"])
	}
	// OpenUri action present?
	actions, _ := captured["potentialAction"].([]any)
	if len(actions) != 1 {
		t.Errorf("expected 1 potentialAction; got %d", len(actions))
	}
}

func TestTeams_BulletConversion(t *testing.T) {
	// Verify the markdown adapter swaps "- " for "• " so Teams
	// doesn't render bullets inconsistently across mobile/desktop.
	out := teamsConvertMarkdown("intro\n- one\n- two\n- three")
	if !strings.Contains(out, "• one") || !strings.Contains(out, "• two") {
		t.Errorf("bullet conversion failed: %q", out)
	}
}
