package report

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// Compile-time assertion.
var _ core.Reporter = (*HTMLReporter)(nil)

func TestHTML_Format(t *testing.T) {
	if got := NewHTML().Format(); got != "html" {
		t.Errorf("Format() = %q, want html", got)
	}
}

func TestHTML_RenderEmptyProducesValidPage(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTML().Render(context.Background(), nil, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	// Doctype and lang attribute (accessibility).
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("output should start with HTML5 doctype")
	}
	if !strings.Contains(out, `lang="en"`) {
		t.Error("html tag should declare lang=en")
	}

	// Empty-state message.
	if !strings.Contains(out, "No findings") {
		t.Errorf("empty render should show 'No findings' message, got:\n%s", out[:min(500, len(out))])
	}
}

func TestHTML_RenderEmitsFindingsGroupedBySeverity(t *testing.T) {
	findings := []core.Finding{
		{
			CheckID:  "low-check",
			Status:   core.StatusFail,
			Severity: core.SeverityLow,
			Resource: core.ResourceRef{ID: "r1", Name: "host-low", Type: "linux.host"},
			Message:  "low-priority gap",
		},
		{
			CheckID:  "critical-check",
			Status:   core.StatusFail,
			Severity: core.SeverityCritical,
			Resource: core.ResourceRef{ID: "r2", Name: "host-crit", Type: "digitalocean.droplet"},
			Message:  "critical exposure",
		},
	}

	var buf bytes.Buffer
	if err := NewHTML().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	// Both finding IDs appear in output.
	if !strings.Contains(out, "critical-check") {
		t.Error("output missing critical-check")
	}
	if !strings.Contains(out, "low-check") {
		t.Error("output missing low-check")
	}

	// Resource names appear.
	if !strings.Contains(out, "host-crit") || !strings.Contains(out, "host-low") {
		t.Error("output missing resource names")
	}

	// Critical section header appears before Low section header.
	criticalAt := strings.Index(out, "Critical (")
	lowAt := strings.Index(out, "Low (")
	if criticalAt < 0 || lowAt < 0 {
		t.Fatal("severity section header missing in output")
	}
	if criticalAt > lowAt {
		t.Error("Critical section should appear before Low section")
	}
}

func TestHTML_RenderIncludesPassFindings(t *testing.T) {
	// Unlike Markdown (PR summary), HTML emits everything -- the
	// audience opens the file in a browser and wants the full picture.
	findings := []core.Finding{
		{
			CheckID:  "passing-check",
			Status:   core.StatusPass,
			Severity: core.SeverityHigh,
			Resource: core.ResourceRef{ID: "r", Name: "ok-host", Type: "linux.host"},
			Message:  "passed",
		},
	}
	var buf bytes.Buffer
	if err := NewHTML().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "passing-check") {
		t.Error("HTML should include pass findings (unlike Markdown)")
	}
}

func TestHTML_RenderIncludesEmbeddedCSSAndJS(t *testing.T) {
	var buf bytes.Buffer
	_ = NewHTML().Render(context.Background(), nil, nil, &buf)
	out := buf.String()
	if !strings.Contains(out, "<style>") || !strings.Contains(out, "</style>") {
		t.Error("HTML should embed CSS inline (single-file requirement)")
	}
	if !strings.Contains(out, "<script>") || !strings.Contains(out, "</script>") {
		t.Error("HTML should embed JS inline (single-file requirement)")
	}
	// Dark theme sentinel: --bg variable is part of the dark palette.
	if !strings.Contains(out, "--bg:") {
		t.Error("CSS appears to be missing the theme variables")
	}
}

func TestHTML_FactoryNew(t *testing.T) {
	r, err := New("html")
	if err != nil {
		t.Fatalf("New(html): %v", err)
	}
	if r.Format() != "html" {
		t.Errorf("got %q, want html", r.Format())
	}
}

func TestCapitalize(t *testing.T) {
	cases := map[string]string{
		"critical": "Critical",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
		"info":     "Info",
		"unknown":  "unknown", // not handled -> passes through unchanged
	}
	for in, want := range cases {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// v0.22.1 — inline remediation-snippet rendering. Registers a fake
// Strategy for a fixed CheckID + verifies the HTML carries the
// snippet's Format, Risk class, Content, VerifyCmd, and Notes inline
// under the per-finding Details block.
func TestHTML_RendersRemediationSnippetsInline(t *testing.T) {
	fakeStrategy := &fakeHTMLStrategy{
		name:    "html-test-fake",
		checkID: "html-test-check",
		formats: []remediate.Format{remediate.FormatBash, remediate.FormatTerraform},
		snippets: map[remediate.Format]remediate.Snippet{
			remediate.FormatBash: {
				Risk:      remediate.RiskSafe,
				Content:   "echo 'fix me'",
				VerifyCmd: "echo verify",
				Notes:     "test note",
			},
			remediate.FormatTerraform: {
				Risk:    remediate.RiskReview,
				Content: `resource "fake" "x" {}`,
			},
		},
	}
	remediate.Default.Register(fakeStrategy)
	t.Cleanup(func() { remediate.Default = remediate.NewRegistry() })

	findings := []core.Finding{
		{
			CheckID:  "html-test-check",
			Status:   core.StatusFail,
			Severity: core.SeverityHigh,
			Resource: core.ResourceRef{ID: "r1", Name: "demo", Type: "fake.type"},
			Message:  "failing for the test",
		},
	}
	var buf bytes.Buffer
	if err := NewHTML().Render(context.Background(), findings, nil, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	cases := []struct {
		needle string
		desc   string
	}{
		{`class="snippets"`, "snippets container present"},
		{`data-snippet-tab="bash"`, "bash tab button"},
		{`data-snippet-tab="terraform"`, "terraform tab button"},
		{`<pre>echo &#39;fix me&#39;</pre>`, "bash content HTML-escaped"},
		{`<pre>resource &#34;fake&#34; &#34;x&#34; {}</pre>`, "terraform content HTML-escaped"},
		{`class="risk safe"`, "safe risk class applied"},
		{`class="risk review"`, "review risk class applied"},
		{`<code>echo verify</code>`, "verify command rendered"},
		{`test note`, "notes rendered"},
	}
	for _, c := range cases {
		if !strings.Contains(out, c.needle) {
			t.Errorf("%s: missing %q in HTML output", c.desc, c.needle)
		}
	}
}

// fakeHTMLStrategy is a minimal remediate.Strategy for the snippet-
// inline test above. Lives in this file (not a shared testutil) so
// the test's contract is self-contained.
type fakeHTMLStrategy struct {
	name     string
	checkID  string
	formats  []remediate.Format
	snippets map[remediate.Format]remediate.Snippet
}

func (s *fakeHTMLStrategy) Name() string                { return s.name }
func (s *fakeHTMLStrategy) CheckIDs() []string          { return []string{s.checkID} }
func (s *fakeHTMLStrategy) Formats() []remediate.Format { return s.formats }
func (s *fakeHTMLStrategy) Render(_ core.Finding, f remediate.Format) (remediate.Snippet, error) {
	snip, ok := s.snippets[f]
	if !ok {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return snip, nil
}
