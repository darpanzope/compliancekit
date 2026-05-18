package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestPagerDuty_NotConfigured(t *testing.T) {
	if NewPagerDuty(PagerDutyConfig{}).Configured() {
		t.Errorf("empty config should not be Configured")
	}
}

func TestPagerDuty_DefaultsToCriticalThreshold(t *testing.T) {
	// PD pages humans — default must be critical-only so a fresh
	// install doesn't wake on-call on medium findings.
	sink := NewPagerDuty(PagerDutyConfig{IntegrationKey: "key"})
	if sink.Threshold() != compliancekit.SeverityCritical {
		t.Errorf("Threshold = %v, want critical (default)", sink.Threshold())
	}

	// Explicit override is honored.
	custom := NewPagerDuty(PagerDutyConfig{IntegrationKey: "key", SeverityFloor: compliancekit.SeverityHigh})
	if custom.Threshold() != compliancekit.SeverityHigh {
		t.Errorf("explicit override should win: %v", custom.Threshold())
	}
}

func TestPagerDuty_EventShape(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success","message":"Event processed","dedup_key":"abc"}`))
	}))
	defer srv.Close()

	sink := NewPagerDuty(PagerDutyConfig{
		IntegrationKey: "00112233445566778899aabbccddeeff",
		Source:         "compliancekit-test",
		EventsURL:      srv.URL,
		SeverityFloor:  compliancekit.SeverityInfo,
		HTTPClient:     srv.Client(),
	})
	notifications := BuildNotifications([]compliancekit.Finding{
		sampleFinding("aws-iam-root-mfa", "critical"),
	}, BuildOptions{URLPrefix: "https://compliance.x"})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("Sent = %d", res.Sent)
	}
	if captured["routing_key"] != "00112233445566778899aabbccddeeff" {
		t.Errorf("routing_key = %v", captured["routing_key"])
	}
	if captured["event_action"] != "trigger" {
		t.Errorf("event_action = %v", captured["event_action"])
	}
	if captured["dedup_key"] == nil || captured["dedup_key"] == "" {
		t.Errorf("dedup_key missing (should be notification fingerprint)")
	}
	payload, _ := captured["payload"].(map[string]any)
	if payload["severity"] != "critical" {
		t.Errorf("payload.severity = %v, want critical", payload["severity"])
	}
	if !strings.Contains(payload["summary"].(string), "aws-iam-root-mfa") {
		t.Errorf("summary missing CheckID: %v", payload["summary"])
	}
	if payload["source"] != "compliancekit-test" {
		t.Errorf("source = %v", payload["source"])
	}
}

func TestPDSeverityMapping(t *testing.T) {
	cases := []struct {
		in  compliancekit.Severity
		out string
	}{
		{compliancekit.SeverityCritical, "critical"},
		{compliancekit.SeverityHigh, "error"},
		{compliancekit.SeverityMedium, "warning"},
		{compliancekit.SeverityLow, "info"},
	}
	for _, c := range cases {
		if got := pdSeverity(c.in); got != c.out {
			t.Errorf("pdSeverity(%v) = %q, want %q", c.in, got, c.out)
		}
	}
}
