package checkov

import (
	"context"
	"os"
	"path/filepath"
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
	got, ok := ingest.Default.Lookup("checkov-json")
	if !ok {
		t.Fatalf("checkov-json not registered")
	}
	if got.Format() != "checkov-json" {
		t.Errorf("Format = %q", got.Format())
	}
}

func TestIngest_Terraform(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "terraform.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3 (2 failed + 1 skipped)", len(r.Findings))
	}

	var failHigh, failMedium, skipped *compliancekit.Finding
	for i := range r.Findings {
		switch r.Findings[i].CheckID {
		case "ingest.checkov.CKV_AWS_24":
			failHigh = &r.Findings[i]
		case "ingest.checkov.CKV_AWS_19":
			failMedium = &r.Findings[i]
		case "ingest.checkov.CKV_AWS_21":
			skipped = &r.Findings[i]
		}
	}
	if failHigh == nil || failHigh.Status != compliancekit.StatusFail || failHigh.Severity != compliancekit.SeverityHigh {
		t.Errorf("CKV_AWS_24 finding = %+v", failHigh)
	}
	if failMedium == nil || failMedium.Severity != compliancekit.SeverityMedium {
		t.Errorf("CKV_AWS_19 finding = %+v", failMedium)
	}
	if skipped == nil || skipped.Status != compliancekit.StatusSkip {
		t.Errorf("CKV_AWS_21 skipped finding = %+v", skipped)
	}

	// Phantom resource should preserve Terraform resource id + file
	// path in Attributes.
	if r.Resources[0].Type != "checkov.terraform.resource" {
		t.Errorf("Resource.Type = %q", r.Resources[0].Type)
	}
	if r.Resources[0].Attributes["file_path"] != "/main.tf" {
		t.Errorf("Resource.Attributes[file_path] = %v", r.Resources[0].Attributes["file_path"])
	}
}

func TestSeverityFromCheckov(t *testing.T) {
	cases := []struct {
		in   string
		want compliancekit.Severity
	}{
		{"CRITICAL", compliancekit.SeverityCritical},
		{"HIGH", compliancekit.SeverityHigh},
		{"medium", compliancekit.SeverityMedium},
		{"LOW", compliancekit.SeverityLow},
		{"INFO", compliancekit.SeverityInfo},
		{"", compliancekit.SeverityMedium}, // blank → medium fallback for failed checks
	}
	for _, c := range cases {
		got := severityFromCheckov(c.in)
		if got != c.want {
			t.Errorf("severityFromCheckov(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
