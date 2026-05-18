package ocsf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/ingest"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
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
	got, ok := ingest.Default.Lookup("ocsf")
	if !ok {
		t.Fatalf("ocsf adapter not registered")
	}
	if got.Format() != "ocsf" {
		t.Errorf("Format() = %q", got.Format())
	}
}

// Security Hub JSON array shape.
func TestIngest_SecurityHubArray(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "aws-security-hub.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d", len(r.Findings))
	}

	// First finding: S3.5 SSL-only → high severity, mapped to soc2 CC6.6 + pci 4.2
	f := r.Findings[0]
	if f.CheckID != "ingest.aws-security-hub.S3.5" {
		t.Errorf("CheckID = %q", f.CheckID)
	}
	if f.Severity != compliancekit.SeverityHigh {
		t.Errorf("Severity = %v, want high", f.Severity)
	}
	if f.Source == nil || f.Source.Tool != "aws-security-hub" {
		t.Errorf("Source = %+v", f.Source)
	}
	if f.Resource.AccountID != "123456789012" {
		t.Errorf("Resource.AccountID = %q", f.Resource.AccountID)
	}
	if f.Resource.Region != "us-east-1" {
		t.Errorf("Resource.Region = %q", f.Resource.Region)
	}

	// Second finding: EC2.19 → critical
	if r.Findings[1].Severity != compliancekit.SeverityCritical {
		t.Errorf("EC2.19 Severity = %v, want critical", r.Findings[1].Severity)
	}
}

// GCP SCC JSONL shape.
func TestIngest_SCCJSONL(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "gcp-scc.jsonl"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	if r.Findings[0].CheckID != "ingest.gcp-scc.PUBLIC_BUCKET_ACL" {
		t.Errorf("CheckID = %q", r.Findings[0].CheckID)
	}
	if r.Findings[0].Severity != compliancekit.SeverityCritical {
		t.Errorf("Severity = %v", r.Findings[0].Severity)
	}
}

// Defender single-object shape.
func TestIngest_DefenderSingleObject(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "defender.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	if !strings.Contains(r.Findings[0].CheckID, "NSG_RULE_ALLOW_ALL_INBOUND") {
		t.Errorf("CheckID = %q", r.Findings[0].CheckID)
	}
	if r.Findings[0].Severity != compliancekit.SeverityCritical {
		t.Errorf("Severity = %v", r.Findings[0].Severity)
	}
}

func TestCanonicalProduct(t *testing.T) {
	cases := []struct {
		explicit string
		name     string
		vendor   string
		want     string
	}{
		{"", "Security Hub", "Amazon Web Services", "aws-security-hub"},
		{"", "SecurityHub", "AWS", "aws-security-hub"},
		{"", "Security Command Center", "Google Cloud", "gcp-scc"},
		{"", "Microsoft Defender for Cloud", "Microsoft", "defender-for-cloud"},
		{"", "Prowler", "Prowler Pro", "prowler"},
		{"explicit", "ignored", "ignored", "explicit"},
		{"", "Unknown", "Vendor", "unknown"},
	}
	for _, c := range cases {
		got := canonicalProduct(c.explicit, product{Name: c.name, Vendor: c.vendor})
		if got != c.want {
			t.Errorf("canonicalProduct(%q, %q, %q) = %q, want %q",
				c.explicit, c.name, c.vendor, got, c.want)
		}
	}
}

func TestResolveStatus(t *testing.T) {
	cases := []struct {
		ev   event
		want compliancekit.Status
	}{
		{event{StatusID: 4}, compliancekit.StatusPass},
		{event{StatusID: 3}, compliancekit.StatusSkip},
		{event{StatusID: 1}, compliancekit.StatusFail},
		{event{Compliance: &complianceObj{StatusID: 1}}, compliancekit.StatusPass},
		{event{Compliance: &complianceObj{StatusID: 2}}, compliancekit.StatusFail},
		{event{Compliance: &complianceObj{StatusID: 3}}, compliancekit.StatusSkip},
	}
	for _, c := range cases {
		got := resolveStatus(c.ev)
		if got != c.want {
			t.Errorf("resolveStatus(%+v) = %v, want %v", c.ev, got, c.want)
		}
	}
}

func TestBuiltinProducts(t *testing.T) {
	prods := BuiltinProducts()
	have := map[string]bool{}
	for _, p := range prods {
		have[p] = true
	}
	for _, want := range []string{"aws-security-hub", "gcp-scc", "defender-for-cloud"} {
		if !have[want] {
			t.Errorf("BuiltinProducts missing %q (got %v)", want, prods)
		}
	}
}
