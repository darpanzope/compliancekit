package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
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
	findings := []core.Finding{
		{Status: core.StatusPass, Severity: core.SeverityCritical}, // pass: not actionable
		{Status: core.StatusFail, Severity: core.SeverityLow},      // below threshold
		{Status: core.StatusFail, Severity: core.SeverityHigh},     // matches
	}
	if !hasActionableAtOrAbove(findings, core.SeverityHigh) {
		t.Error("expected actionable high finding to count")
	}
	if hasActionableAtOrAbove(findings, core.SeverityCritical) {
		t.Error("no critical findings exist, but function returned true")
	}
}

func TestHasActionableAtOrAbove_ErrorCounts(t *testing.T) {
	findings := []core.Finding{
		{Status: core.StatusError, Severity: core.SeverityMedium},
	}
	if !hasActionableAtOrAbove(findings, core.SeverityMedium) {
		t.Error("error findings should be actionable")
	}
}

func TestPrintSummary_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	printSummary(&buf, nil)
	if !strings.Contains(buf.String(), "0 findings") {
		t.Errorf("expected '0 findings' in output, got: %q", buf.String())
	}
}

func TestPrintSummary_CountsBySeverity(t *testing.T) {
	findings := []core.Finding{
		{Status: core.StatusFail, Severity: core.SeverityCritical},
		{Status: core.StatusFail, Severity: core.SeverityHigh},
		{Status: core.StatusFail, Severity: core.SeverityHigh},
		{Status: core.StatusFail, Severity: core.SeverityLow},
		{Status: core.StatusPass, Severity: core.SeverityHigh}, // ignored
	}
	var buf bytes.Buffer
	printSummary(&buf, findings)
	out := buf.String()
	if !strings.Contains(out, "4 findings") {
		t.Errorf("expected '4 findings', got: %q", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected '1 critical', got: %q", out)
	}
	if !strings.Contains(out, "2 high") {
		t.Errorf("expected '2 high', got: %q", out)
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
