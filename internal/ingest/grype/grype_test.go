package grype

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
	got, ok := ingest.Default.Lookup("grype-json")
	if !ok {
		t.Fatalf("grype-json adapter not registered")
	}
	if got.Format() != "grype-json" {
		t.Errorf("Format = %q", got.Format())
	}
}

func TestIngest_ImageScan(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "image-scan.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Vulnerability == nil {
		t.Fatalf("Vulnerability block nil")
	}
	if f.Vulnerability.ID != "CVE-2024-12345" {
		t.Errorf("ID = %q", f.Vulnerability.ID)
	}
	if f.Vulnerability.CVSSScore != 8.1 {
		t.Errorf("CVSSScore = %v, want 8.1 (nvd preferred)", f.Vulnerability.CVSSScore)
	}
	if f.Vulnerability.FixedVersion != "3.0.8" {
		t.Errorf("FixedVersion = %q", f.Vulnerability.FixedVersion)
	}
	if !strings.Contains(f.Vulnerability.Package.PURL, "pkg:apk") {
		t.Errorf("PURL = %q", f.Vulnerability.Package.PURL)
	}
	if f.Resource.Type != "container.image" {
		t.Errorf("Resource.Type = %q", f.Resource.Type)
	}
	if !strings.HasPrefix(f.Resource.ID, "container-image://") {
		t.Errorf("Resource.ID = %q", f.Resource.ID)
	}
	if f.Severity != compliancekit.SeverityHigh {
		t.Errorf("Severity = %v", f.Severity)
	}
}

func TestSeverityFromGrype(t *testing.T) {
	cases := []struct {
		in   string
		want compliancekit.Severity
	}{
		{"Critical", compliancekit.SeverityCritical},
		{"high", compliancekit.SeverityHigh},
		{"Medium", compliancekit.SeverityMedium},
		{"low", compliancekit.SeverityLow},
		{"Negligible", compliancekit.SeverityInfo},
		{"", compliancekit.SeverityInfo},
	}
	for _, c := range cases {
		got := severityFromGrype(c.in)
		if got != c.want {
			t.Errorf("severityFromGrype(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPreferredCVSS(t *testing.T) {
	in := []cvssEntry{
		{Source: "redhat", Version: "3.1", Metrics: cvssMetrics{BaseScore: 7.5}},
		{Source: "nvd", Version: "3.1", Metrics: cvssMetrics{BaseScore: 8.1}},
	}
	got := preferredCVSS(in)
	if got.Metrics.BaseScore != 8.1 {
		t.Errorf("preferredCVSS = %+v, want NVD 8.1", got)
	}
}
