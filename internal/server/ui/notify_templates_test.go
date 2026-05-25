package ui

import (
	"strings"
	"testing"
)

func TestRenderTemplate_Happy(t *testing.T) {
	body := `Sev: {{.severity | upper}} for {{.check_id}}`
	out, perr := renderTemplate(body, defaultSamplePayload())
	if perr != "" {
		t.Fatalf("preview err: %s", perr)
	}
	if !strings.Contains(out, "Sev: HIGH for aws.iam.user.mfa-enabled") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestRenderTemplate_BadTemplate(t *testing.T) {
	_, perr := renderTemplate(`{{ .severity | nope`, defaultSamplePayload())
	if !strings.Contains(perr, "parse error") {
		t.Errorf("expected parse error, got %q", perr)
	}
}

func TestRenderTemplate_BadPayload(t *testing.T) {
	_, perr := renderTemplate(`{{.severity}}`, "not-json")
	if !strings.Contains(perr, "not valid JSON") {
		t.Errorf("expected payload error, got %q", perr)
	}
}

func TestIsKnownNotifyKind(t *testing.T) {
	if !isKnownNotifyKind("slack") {
		t.Errorf("slack should be known")
	}
	if isKnownNotifyKind("madeup") {
		t.Errorf("madeup should NOT be known")
	}
}

func TestDefaultTemplateExistsForEveryKind(t *testing.T) {
	for _, k := range notifyKinds {
		if defaultTemplate(k) == "" {
			t.Errorf("defaultTemplate(%q) empty", k)
		}
	}
}
