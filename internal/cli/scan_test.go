package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/ui"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestBuildReporters_DefaultsToJSON(t *testing.T) {
	rs, err := buildReporters(nil)
	if err != nil {
		t.Fatalf("buildReporters: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("len(reporters) = %d, want 1", len(rs))
	}
	if rs[0].Format() != "json" {
		t.Errorf("default Format = %q, want json", rs[0].Format())
	}
}

func TestBuildReporters_UnknownFormatFails(t *testing.T) {
	if _, err := buildReporters([]string{"toml-ohno"}); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestHasActionableAtOrAbove(t *testing.T) {
	findings := []compliancekit.Finding{
		{Status: compliancekit.StatusPass, Severity: compliancekit.SeverityCritical}, // pass: not actionable
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityLow},      // below threshold
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityHigh},     // matches
	}
	if !hasActionableAtOrAbove(findings, compliancekit.SeverityHigh) {
		t.Error("expected actionable high finding to count")
	}
	if hasActionableAtOrAbove(findings, compliancekit.SeverityCritical) {
		t.Error("no critical findings exist, but function returned true")
	}
}

func TestHasActionableAtOrAbove_ErrorCounts(t *testing.T) {
	findings := []compliancekit.Finding{
		{Status: compliancekit.StatusError, Severity: compliancekit.SeverityMedium},
	}
	if !hasActionableAtOrAbove(findings, compliancekit.SeverityMedium) {
		t.Error("error findings should be actionable")
	}
}

// plainStyler builds a Color=false Styler suitable for byte-stable
// snapshot tests of printSummary output. Mirrors the production CI
// path (NO_COLOR / piped output) where the snapshot tests act as
// canaries against accidental color leaks into non-TTY output.
func plainStyler() *ui.Styler {
	return ui.NewStyler(io.Discard, true)
}

func TestPrintSummary_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	printSummary(&buf, plainStyler(), nil)
	if !strings.Contains(buf.String(), "0 findings") {
		t.Errorf("expected '0 findings' in output, got: %q", buf.String())
	}
}

func TestPrintSummary_CountsBySeverity(t *testing.T) {
	findings := []compliancekit.Finding{
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityCritical},
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityHigh},
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityHigh},
		{Status: compliancekit.StatusFail, Severity: compliancekit.SeverityLow},
		{Status: compliancekit.StatusPass, Severity: compliancekit.SeverityHigh}, // ignored
	}
	var buf bytes.Buffer
	printSummary(&buf, plainStyler(), findings)
	out := buf.String()
	if !strings.Contains(out, "4 findings") {
		t.Errorf("expected '4 findings', got: %q", out)
	}
	// Counts are now severity-chip-formatted: "1 [CRITICAL]" etc.
	if !strings.Contains(out, "1 [CRITICAL]") {
		t.Errorf("expected '1 [CRITICAL]', got: %q", out)
	}
	if !strings.Contains(out, "2 [HIGH]") {
		t.Errorf("expected '2 [HIGH]', got: %q", out)
	}
}

func TestExitCodeError(t *testing.T) {
	err := NewExitCode(2, "%d things wrong", 7)
	if err.ExitCode() != 2 {
		t.Errorf("ExitCode() = %d, want 2", err.ExitCode())
	}
	if !strings.Contains(err.Error(), "7 things wrong") {
		t.Errorf("Error() = %q, want substring '7 things wrong'", err.Error())
	}
}
