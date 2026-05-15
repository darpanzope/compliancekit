package sarif

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/ingest"
)

func mustOpen(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestSelfRegistered(t *testing.T) {
	got, ok := ingest.Default.Lookup("sarif")
	if !ok {
		t.Fatalf("sarif adapter not registered with Default")
	}
	if got.Format() != "sarif" {
		t.Fatalf("Format() = %q, want sarif", got.Format())
	}
	if got.Description() == "" {
		t.Fatalf("Description() empty")
	}
}

// TestIngest_Trivy verifies the Trivy fixture parses into three findings
// with the expected resource projection and severity. The mapping table
// covers the misconfig rules but NOT the CVE (which is intentional —
// per-CVE mapping is impractical, so we emit unmapped + warning).
func TestIngest_Trivy(t *testing.T) {
	a := adapter{}
	opts := ingest.Options{
		Provenance: ingest.Provenance{
			Tool:        "trivy",
			ToolVersion: "0.50.4",
			Format:      "sarif",
			File:        "testdata/trivy.sarif",
			IngestedAt:  time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		},
	}

	r, err := a.Ingest(context.Background(), mustOpen(t, "trivy.sarif"), opts)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(r.Findings))
	}
	if len(r.Resources) != 3 {
		t.Fatalf("want 3 phantom resources, got %d", len(r.Resources))
	}

	// Spot-check the first finding — SG world-open should map to CC6.6 + SC-7 + 1.4
	// via the bundled mapping; severity stays at critical (mapping override).
	first := r.Findings[0]
	if first.CheckID != "ingest.trivy.AVD-AWS-0107" {
		t.Errorf("CheckID = %q", first.CheckID)
	}
	if first.Severity != core.SeverityCritical {
		t.Errorf("Severity = %v, want critical", first.Severity)
	}
	if first.Source == nil || first.Source.Tool != "trivy" || first.Source.Format != "sarif" {
		t.Errorf("Source = %+v", first.Source)
	}

	// Phantom resource: should reflect the IaC file with a terraform.file kind.
	if r.Resources[0].Type != "terraform.file" {
		t.Errorf("first phantom Type = %q, want terraform.file", r.Resources[0].Type)
	}

	// CVE finding has no built-in mapping → should generate a warning.
	if len(r.Warnings) != 1 {
		t.Errorf("warnings = %v (want 1 for unmapped CVE)", r.Warnings)
	}
}

// TestIngest_Checkov verifies Terraform logical-location projection
// onto resource names ("aws_security_group.web", etc.).
func TestIngest_Checkov(t *testing.T) {
	a := adapter{}
	opts := ingest.Options{
		Provenance: ingest.Provenance{Tool: "checkov", IngestedAt: time.Now().UTC()},
	}

	r, err := a.Ingest(context.Background(), mustOpen(t, "checkov.sarif"), opts)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(r.Findings))
	}

	// First finding: SG SSH world-open → critical via mapping override.
	if r.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("CKV_AWS_24 Severity = %v, want critical", r.Findings[0].Severity)
	}
	// Resource name should come from fullyQualifiedName.
	if !strings.Contains(r.Findings[0].Resource.Name, "aws_security_group.web") {
		t.Errorf("Resource.Name = %q, expected aws_security_group.web", r.Findings[0].Resource.Name)
	}
}

func TestIngest_KICS(t *testing.T) {
	a := adapter{}
	r, err := a.Ingest(context.Background(), mustOpen(t, "kics.sarif"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(r.Findings))
	}
	if r.Findings[0].Source.Tool != "kics" {
		t.Errorf("Source.Tool = %q, want kics", r.Findings[0].Source.Tool)
	}
}

func TestIngest_Terrascan(t *testing.T) {
	a := adapter{}
	r, err := a.Ingest(context.Background(), mustOpen(t, "terrascan.sarif"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(r.Findings))
	}
	if r.Findings[0].Source.Tool != "terrascan" {
		t.Errorf("Source.Tool = %q, want terrascan", r.Findings[0].Source.Tool)
	}
}

func TestCanonicalTool(t *testing.T) {
	cases := []struct {
		explicit string
		driver   string
		want     string
	}{
		{"", "Trivy", "trivy"},
		{"", "trivy", "trivy"},
		{"", "Checkov", "checkov"},
		{"", "bridgecrew/checkov", "checkov"},
		{"", "KICS", "kics"},
		{"", "terrascan", "terrascan"},
		{"", "Unknown Tool", "unknown tool"},
		{"semgrep", "ignored", "semgrep"}, // explicit wins
	}
	for _, c := range cases {
		got := canonicalTool(c.explicit, c.driver)
		if got != c.want {
			t.Errorf("canonicalTool(%q, %q) = %q, want %q", c.explicit, c.driver, got, c.want)
		}
	}
}

func TestCVSSToSeverity(t *testing.T) {
	cases := []struct {
		v    any
		want core.Severity
	}{
		{"9.8", core.SeverityCritical},
		{"7.5", core.SeverityHigh},
		{"5.0", core.SeverityMedium},
		{"2.0", core.SeverityLow},
		{"0", core.SeverityInfo},
		{8.1, core.SeverityHigh},
		{"garbage", core.SeverityInfo},
		{nil, core.SeverityInfo},
	}
	for _, c := range cases {
		got := cvssToSeverity(c.v)
		if got != c.want {
			t.Errorf("cvssToSeverity(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestFailOnUnmapped(t *testing.T) {
	a := adapter{}
	opts := ingest.Options{
		Provenance:     ingest.Provenance{Tool: "trivy"},
		FailOnUnmapped: true,
	}
	_, err := a.Ingest(context.Background(), mustOpen(t, "trivy.sarif"), opts)
	if err == nil {
		t.Fatalf("expected fail-on-unmapped error for CVE rule with no mapping")
	}
	if !strings.Contains(err.Error(), "no mapping") {
		t.Fatalf("error = %v, want 'no mapping' phrase", err)
	}
}

func TestComposeCheckID(t *testing.T) {
	cases := []struct {
		tool, rule, want string
	}{
		{"trivy", "CVE-2024-1", "ingest.trivy.CVE-2024-1"},
		{"checkov", "CKV/AWS/18", "ingest.checkov.CKV.AWS.18"},
		{"x", "", "ingest.x.unspecified"},
	}
	for _, c := range cases {
		got := composeCheckID(c.tool, c.rule)
		if got != c.want {
			t.Errorf("composeCheckID(%q,%q) = %q, want %q", c.tool, c.rule, got, c.want)
		}
	}
}

func TestBuiltinTools(t *testing.T) {
	tools := BuiltinTools()
	have := map[string]bool{}
	for _, t := range tools {
		have[t] = true
	}
	for _, want := range []string{"trivy", "checkov", "kics", "terrascan"} {
		if !have[want] {
			t.Errorf("BuiltinTools missing %q (got %v)", want, tools)
		}
	}
}
