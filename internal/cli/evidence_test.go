package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Side-effect imports: populate the default check registry so the
	// evidence packer can resolve framework mappings, mirroring
	// cmd/compliancekit/main.go.
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
	_ "github.com/darpanzope/compliancekit/internal/checks/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// scanEnvelopeForTest matches the JSON shape internal/report.JSONReporter
// emits, narrowed to the fields runEvidence reads. Tests synthesize this
// directly so they do not need to invoke a full scan run.
type scanEnvelopeForTest struct {
	Schema   string         `json:"schema"`
	Findings []core.Finding `json:"findings"`
}

func writeFindingsFile(t *testing.T, path string, findings []core.Finding) {
	t.Helper()
	envelope := scanEnvelopeForTest{
		Schema:   "compliancekit.v1",
		Findings: findings,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkCLIFinding(checkID, resourceID string) core.Finding {
	return core.Finding{
		CheckID:  checkID,
		Status:   core.StatusFail,
		Severity: core.SeverityHigh,
		Resource: core.ResourceRef{
			ID:       resourceID,
			Type:     "digitalocean.droplet",
			Name:     resourceID,
			Provider: "digitalocean",
		},
		Message: "synthetic fail",
	}
}

func TestRunEvidence_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "findings.json")
	out := filepath.Join(dir, "pack")
	writeFindingsFile(t, in, []core.Finding{
		mkCLIFinding("do-droplet-no-firewall", "droplet-1"),
	})

	var buf bytes.Buffer
	err := runEvidence(context.Background(), &buf, evidenceOptions{
		in:     in,
		out:    out,
		period: "2026-Q2",
	})
	if err != nil {
		t.Fatalf("runEvidence: %v", err)
	}

	// Output mentions both summary metrics and per-framework counts.
	for _, want := range []string{
		"Generating evidence pack",
		"SOC 2 Trust Services Criteria",
		"ISO/IEC 27001:2022 Annex A",
		"CIS Controls v8",
		"MANIFEST.sha256",
		"Auditor index:",
		"Control mapping:",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q\n---\n%s", want, buf.String())
		}
	}

	// Pack root has the canonical four top-level entries.
	for _, name := range []string{"MANIFEST.sha256", "control-mapping.csv", "summary.html"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestRunEvidence_MissingInputErrors(t *testing.T) {
	dir := t.TempDir()
	err := runEvidence(context.Background(), &bytes.Buffer{}, evidenceOptions{
		in:  filepath.Join(dir, "does-not-exist.json"),
		out: filepath.Join(dir, "pack"),
	})
	if err == nil {
		t.Error("expected error for missing input")
	}
}

func TestRunEvidence_EmptyFindingsErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "empty.json")
	writeFindingsFile(t, in, nil)
	err := runEvidence(context.Background(), &bytes.Buffer{}, evidenceOptions{
		in:  in,
		out: filepath.Join(dir, "pack"),
	})
	if err == nil || !strings.Contains(err.Error(), "no findings") {
		t.Errorf("expected 'no findings' error, got: %v", err)
	}
}

func TestRunEvidence_AcceptsRawArray(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "findings.json")

	// Raw array form (jq -r '.findings' produces this).
	arr := []core.Finding{mkCLIFinding("do-droplet-no-firewall", "droplet-1")}
	data, err := json.Marshal(arr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}

	err = runEvidence(context.Background(), &bytes.Buffer{}, evidenceOptions{
		in:  in,
		out: filepath.Join(dir, "pack"),
	})
	if err != nil {
		t.Fatalf("runEvidence with raw array: %v", err)
	}
}

func TestRunEvidence_RequiresOut(t *testing.T) {
	err := runEvidence(context.Background(), &bytes.Buffer{}, evidenceOptions{
		in: "findings.json",
	})
	if err == nil || !strings.Contains(err.Error(), "--out") {
		t.Errorf("expected '--out is required' error, got: %v", err)
	}
}
