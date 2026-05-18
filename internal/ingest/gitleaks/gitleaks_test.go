package gitleaks

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
	got, ok := ingest.Default.Lookup("gitleaks-json")
	if !ok {
		t.Fatalf("gitleaks-json not registered")
	}
	if got.Format() != "gitleaks-json" {
		t.Errorf("Format = %q", got.Format())
	}
}

func TestIngest_Sample(t *testing.T) {
	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "sample.json"), ingest.Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("Findings = %d", len(r.Findings))
	}

	for _, f := range r.Findings {
		if f.Secret == nil {
			t.Errorf("Finding %s has nil Secret block", f.CheckID)
			continue
		}
		// ADR-010 property: raw secret value never appears in output.
		if strings.Contains(f.Secret.Fingerprint, "AKIAIOSFODNN7EXAMPLE") ||
			strings.Contains(f.Secret.Fingerprint, "abc123def456ghi789") {
			t.Errorf("raw secret leaked into Fingerprint: %q", f.Secret.Fingerprint)
		}
		if f.Secret.Fingerprint == "" {
			t.Errorf("Fingerprint empty for %s", f.CheckID)
		}
	}

	// aws-access-key-id rule → critical severity per heuristic.
	awsFinding := r.Findings[0]
	if awsFinding.Severity != compliancekit.SeverityCritical {
		t.Errorf("aws-access-key-id severity = %v, want critical", awsFinding.Severity)
	}

	// Commit + author metadata preserved.
	if awsFinding.Secret.Commit == "" || awsFinding.Secret.Author == "" {
		t.Errorf("Secret metadata not propagated: %+v", awsFinding.Secret)
	}
}

func TestSeverityFromGitleaks(t *testing.T) {
	cases := []struct {
		ruleID string
		want   compliancekit.Severity
	}{
		{"aws-access-key-id", compliancekit.SeverityCritical},
		{"stripe-secret-key", compliancekit.SeverityCritical},
		{"private-key", compliancekit.SeverityCritical},
		{"github-pat-token", compliancekit.SeverityHigh},
		{"generic-api-key", compliancekit.SeverityHigh},
		{"weird-rule", compliancekit.SeverityMedium},
	}
	for _, c := range cases {
		got := severityFromGitleaks(c.ruleID)
		if got != c.want {
			t.Errorf("severityFromGitleaks(%q) = %v, want %v", c.ruleID, got, c.want)
		}
	}
}

func TestRedactSecret_NoLeak(t *testing.T) {
	cases := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"SAMPLE_LONG_REDACTION_TEST_FIXTURE_12345",
		"abc123def456",
		"short",
		"",
	}
	for _, in := range cases {
		got := redactSecret(in)
		// Empty input → empty output.
		if in == "" {
			if got != "" {
				t.Errorf("empty input → %q", got)
			}
			continue
		}
		// For any non-empty input, the substring from index 4 to len-4
		// (the "middle" of the original) MUST NOT appear in the
		// output. We pick that window so short secrets that hash also
		// pass without false positives.
		if len(in) >= 16 {
			middle := in[4 : len(in)-4]
			if strings.Contains(got, middle) {
				t.Errorf("middle %q leaked in redacted form %q", middle, got)
			}
		}
	}
}
