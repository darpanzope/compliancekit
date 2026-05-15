package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	got, ok := ingest.Default.Lookup("trivy-json")
	if !ok {
		t.Fatalf("trivy-json adapter not registered")
	}
	if got.Format() != "trivy-json" {
		t.Errorf("Format = %q", got.Format())
	}
}

func TestIngest_ImageScan(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "image-scan.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2 (two CVE entries)", len(r.Findings))
	}

	// Both findings should carry a populated Vulnerability block.
	cve1 := r.Findings[0]
	if cve1.Vulnerability == nil {
		t.Fatalf("first finding has nil Vulnerability block")
	}
	if cve1.Vulnerability.ID != "CVE-2024-12345" {
		t.Errorf("Vulnerability.ID = %q", cve1.Vulnerability.ID)
	}
	if cve1.Vulnerability.CVSSScore != 8.1 {
		t.Errorf("Vulnerability.CVSSScore = %v, want 8.1 (nvd-preferred)", cve1.Vulnerability.CVSSScore)
	}
	if cve1.Vulnerability.FixedVersion != "3.0.8" {
		t.Errorf("FixedVersion = %q", cve1.Vulnerability.FixedVersion)
	}
	if cve1.Vulnerability.Package.PURL == "" {
		t.Errorf("Package.PURL empty")
	}
	if cve1.Severity != core.SeverityHigh {
		t.Errorf("Severity = %v", cve1.Severity)
	}

	// Image SHA from ImageID should be in the phantom resource attrs.
	if len(r.Resources) == 0 {
		t.Fatalf("no phantom resources")
	}
	imageRes := r.Resources[0]
	if imageRes.Type != "container.image" {
		t.Errorf("Resource.Type = %q, want container.image", imageRes.Type)
	}
	if !strings.HasPrefix(imageRes.ID, "container-image://") {
		t.Errorf("Resource.ID = %q, want container-image:// prefix", imageRes.ID)
	}
	if sha, ok := imageRes.Attributes["image_sha"].(string); !ok || sha == "" {
		t.Errorf("Resource.Attributes[image_sha] = %v", imageRes.Attributes["image_sha"])
	}
}

func TestIngest_MisconfigAndSecret(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "fs-with-secret.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2 (misconfig + secret)", len(r.Findings))
	}

	var (
		misconfig *core.Finding
		secret    *core.Finding
	)
	for i := range r.Findings {
		switch {
		case r.Findings[i].Vulnerability != nil:
			t.Errorf("unexpected Vulnerability on non-CVE finding %s", r.Findings[i].CheckID)
		case r.Findings[i].Secret != nil:
			secret = &r.Findings[i]
		default:
			misconfig = &r.Findings[i]
		}
	}
	if misconfig == nil {
		t.Fatalf("misconfig finding not found")
	}
	if secret == nil {
		t.Fatalf("secret finding not found")
	}
	if misconfig.CheckID != "ingest.trivy.AVD-AWS-0086" {
		t.Errorf("misconfig CheckID = %q", misconfig.CheckID)
	}

	// Secret redaction is non-negotiable: raw value MUST NOT appear.
	if strings.Contains(secret.Secret.Fingerprint, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret fingerprint leaked raw value: %q", secret.Secret.Fingerprint)
	}
	if secret.Secret.Fingerprint == "" {
		t.Errorf("secret fingerprint empty")
	}
	if !strings.HasPrefix(secret.Secret.Fingerprint, "AKIA") || !strings.HasSuffix(secret.Secret.Fingerprint, "MPLE") {
		t.Errorf("secret fingerprint shape = %q, want prefix AKIA + suffix MPLE", secret.Secret.Fingerprint)
	}
	if secret.Secret.RuleID != "aws-access-key-id" {
		t.Errorf("Secret.RuleID = %q", secret.Secret.RuleID)
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in    string
		check func(t *testing.T, got string)
	}{
		{"", func(t *testing.T, got string) {
			if got != "" {
				t.Errorf("empty input → %q, want empty", got)
			}
		}},
		{"AKIAIOSFODNN7EXAMPLE", func(t *testing.T, got string) {
			if strings.Contains(got, "IOSFODNN7EXAM") {
				t.Errorf("raw middle leaked: %q", got)
			}
			if !strings.HasPrefix(got, "AKIA") || !strings.HasSuffix(got, "MPLE") {
				t.Errorf("shape = %q, want AKIA...MPLE", got)
			}
		}},
		{"short", func(t *testing.T, got string) {
			if strings.Contains(got, "short") {
				t.Errorf("short secret leaked: %q", got)
			}
			if !strings.HasPrefix(got, "sha256:") {
				t.Errorf("short secret should hash, got %q", got)
			}
		}},
	}
	for _, c := range cases {
		c.check(t, redactSecret(c.in))
	}
}

func TestSeverityFromTrivy(t *testing.T) {
	cases := []struct {
		in   string
		want core.Severity
	}{
		{"CRITICAL", core.SeverityCritical},
		{"High", core.SeverityHigh},
		{"  medium  ", core.SeverityMedium},
		{"LOW", core.SeverityLow},
		{"UNKNOWN", core.SeverityInfo},
		{"", core.SeverityInfo},
	}
	for _, c := range cases {
		got := severityFromTrivy(c.in)
		if got != c.want {
			t.Errorf("severityFromTrivy(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPreferredCVSS(t *testing.T) {
	scores := map[string]cvssDetail{
		"redhat": {V3Score: 7.5, V3Vector: "rh-vector"},
		"nvd":    {V3Score: 8.1, V3Vector: "nvd-vector"},
	}
	got := preferredCVSS(scores)
	if got.V3Score != 8.1 || got.V3Vector != "nvd-vector" {
		t.Errorf("preferredCVSS = %+v, want NVD's 8.1", got)
	}

	// No NVD, any v3 wins.
	got = preferredCVSS(map[string]cvssDetail{"redhat": {V3Score: 7.5}})
	if got.V3Score != 7.5 {
		t.Errorf("preferredCVSS fallback = %+v", got)
	}

	// No v3, falls through to v2.
	got = preferredCVSS(map[string]cvssDetail{"nvd": {V2Score: 5.0}})
	if got.V2Score != 5.0 {
		t.Errorf("preferredCVSS v2 fallback = %+v", got)
	}
}
