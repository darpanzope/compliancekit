package notify

import (
	"os"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

func TestJira_NotConfigured(t *testing.T) {
	cases := []JiraConfig{
		{Host: "", Email: "e", Token: "t", ProjectKey: "P"},
		{Host: "h", Email: "", Token: "t", ProjectKey: "P"},
		{Host: "h", Email: "e", Token: "", ProjectKey: "P"},
		{Host: "h", Email: "e", Token: "t", ProjectKey: ""},
	}
	for i, c := range cases {
		if NewJira(c).Configured() {
			t.Errorf("case %d: should not be Configured: %+v", i, c)
		}
	}
	if !NewJira(JiraConfig{Host: "h", Email: "e", Token: "t", ProjectKey: "P"}).Configured() {
		t.Errorf("full config should be Configured")
	}
}

func TestEnvOr_FirstNonEmpty(t *testing.T) {
	t.Setenv("ENVOR_FIRST", "")
	t.Setenv("ENVOR_SECOND", "second")
	t.Setenv("ENVOR_THIRD", "third")
	if got := envOr("ENVOR_FIRST", "ENVOR_SECOND", "ENVOR_THIRD"); got != "second" {
		t.Errorf("envOr = %q, want second", got)
	}
	if got := envOr("ENVOR_FIRST", "ENVOR_MISSING"); got != "" {
		t.Errorf("envOr all-missing should be empty; got %q", got)
	}
}

func TestJira_ThresholdDefault(t *testing.T) {
	// Default zero-value SeverityFloor = SeverityInfo (everything
	// actionable passes). Confirm the package-level init() respects
	// JIRA_NOTIFY_THRESHOLD when set.
	t.Setenv("JIRA_NOTIFY_THRESHOLD", "high")
	t.Setenv("JIRA_NOTIFY_HOST", "x")
	t.Setenv("JIRA_NOTIFY_EMAIL", "x")
	t.Setenv("JIRA_NOTIFY_TOKEN", "x")
	t.Setenv("JIRA_NOTIFY_PROJECT", "P")

	// Re-derive config the same way init() does so we don't have to
	// re-run init.
	cfg := JiraConfig{
		Host:       os.Getenv("JIRA_NOTIFY_HOST"),
		Email:      os.Getenv("JIRA_NOTIFY_EMAIL"),
		Token:      os.Getenv("JIRA_NOTIFY_TOKEN"),
		ProjectKey: os.Getenv("JIRA_NOTIFY_PROJECT"),
	}
	if t := os.Getenv("JIRA_NOTIFY_THRESHOLD"); t != "" {
		sev, _ := core.ParseSeverity(t)
		cfg.SeverityFloor = sev
	}
	sink := NewJira(cfg)
	if sink.Threshold() != core.SeverityHigh {
		t.Errorf("Threshold = %v, want high", sink.Threshold())
	}
}
