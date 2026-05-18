package report

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Compile-time assertion.
var _ compliancekit.Reporter = (*MarkdownReporter)(nil)

func TestMarkdown_Format(t *testing.T) {
	if got := NewMarkdown().Format(); got != "markdown" {
		t.Errorf("Format() = %q, want markdown", got)
	}
}

func TestMarkdown_RenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := NewMarkdown().Render(context.Background(), nil, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "0 total") {
		t.Errorf("missing 0-total tally:\n%s", out)
	}
	if !strings.Contains(out, "No actionable findings") {
		t.Errorf("expected no-findings note for empty input:\n%s", out)
	}
}

func TestMarkdown_RenderHighSeverityFirst(t *testing.T) {
	findings := []compliancekit.Finding{
		{
			CheckID:  "low-check",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityLow,
			Resource: compliancekit.ResourceRef{Name: "host-1", Type: "linux.host"},
			Message:  "low-priority gap",
		},
		{
			CheckID:  "critical-check",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{Name: "db-01", Type: "digitalocean.droplet"},
			Message:  "critical exposure",
		},
		{
			CheckID:  "high-check",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{Name: "web-01", Type: "linux.host"},
			Message:  "high-priority gap",
		},
	}

	var buf bytes.Buffer
	if err := NewMarkdown().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	// Critical section header must precede High, which precedes Low.
	criticalAt := strings.Index(out, "## Critical findings")
	highAt := strings.Index(out, "## High findings")
	lowAt := strings.Index(out, "## Low findings")
	if criticalAt < 0 || highAt < 0 || lowAt < 0 {
		t.Fatalf("missing section header:\n%s", out)
	}
	if !(criticalAt < highAt && highAt < lowAt) {
		t.Errorf("severity sections out of order: critical=%d high=%d low=%d", criticalAt, highAt, lowAt)
	}

	// Summary table includes every severity row, including zero counts.
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if !strings.Contains(out, "| "+sev+" |") {
			t.Errorf("summary table missing %s row:\n%s", sev, out)
		}
	}
}

func TestMarkdown_OmitsPassAndSkipFromBody(t *testing.T) {
	findings := []compliancekit.Finding{
		{
			CheckID:  "passing-check",
			Status:   compliancekit.StatusPass,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{Name: "ok-host", Type: "linux.host"},
			Message:  "passing finding -- should not appear in body",
		},
		{
			CheckID:  "skipped-check",
			Status:   compliancekit.StatusSkip,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{Name: "skip-host"},
			Message:  "skipped finding -- should not appear in body",
		},
	}

	var buf bytes.Buffer
	if err := NewMarkdown().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "passing-check") {
		t.Errorf("body should not list pass findings:\n%s", out)
	}
	if strings.Contains(out, "skipped-check") {
		t.Errorf("body should not list skip findings:\n%s", out)
	}
	if !strings.Contains(out, "No actionable findings") {
		t.Errorf("expected no-actionable note when all findings are pass/skip:\n%s", out)
	}
}

func TestMarkdown_StableOrderWithinSeverity(t *testing.T) {
	// Same severity, two findings differing in check ID. Output order
	// must be alphabetical by check ID so successive runs produce
	// identical Markdown.
	findings := []compliancekit.Finding{
		{CheckID: "zebra", Status: compliancekit.StatusFail, Severity: compliancekit.SeverityHigh, Resource: compliancekit.ResourceRef{Name: "h1"}},
		{CheckID: "alpha", Status: compliancekit.StatusFail, Severity: compliancekit.SeverityHigh, Resource: compliancekit.ResourceRef{Name: "h1"}},
	}
	var buf bytes.Buffer
	_ = NewMarkdown().Render(context.Background(), findings, nil, &buf)
	out := buf.String()
	alphaAt := strings.Index(out, "**alpha**")
	zebraAt := strings.Index(out, "**zebra**")
	if alphaAt < 0 || zebraAt < 0 {
		t.Fatalf("missing finding marker:\n%s", out)
	}
	if alphaAt > zebraAt {
		t.Errorf("findings within severity not alphabetical: alpha at %d, zebra at %d", alphaAt, zebraAt)
	}
}

func TestMarkdown_FactoryNew(t *testing.T) {
	r, err := New("markdown")
	if err != nil {
		t.Fatalf("New(markdown): %v", err)
	}
	if r.Format() != "markdown" {
		t.Errorf("got %q, want markdown", r.Format())
	}
}
