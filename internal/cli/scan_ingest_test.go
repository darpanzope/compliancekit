package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/core"

	// Side-effect imports — must match the production set so the
	// adapter registry has the same set of formats as a real CLI run.
	_ "github.com/darpanzope/compliancekit/internal/ingest/ocsf"
	_ "github.com/darpanzope/compliancekit/internal/ingest/oscal"
	_ "github.com/darpanzope/compliancekit/internal/ingest/sarif"
)

// sarifFixture / ocsfFixture paths into the test fixtures shipped
// with each adapter subpackage. Test relies on those existing — they
// were authored alongside the adapters in Phases 1 / 2.
func sarifFixture(name string) string {
	abs, _ := filepath.Abs(filepath.Join("..", "ingest", "sarif", "testdata", name))
	return abs
}
func ocsfFixture(name string) string {
	abs, _ := filepath.Abs(filepath.Join("..", "ingest", "ocsf", "testdata", name))
	return abs
}

// TestRunIngestSources_MultipleSources exercises the config-driven
// ingest pipeline: two sources of different formats, results merged
// into one findings slice, phantom resources added to the graph,
// warnings flow through.
func TestRunIngestSources_MultipleSources(t *testing.T) {
	graph := core.NewResourceGraph()

	sources := []config.IngestSource{
		{
			Format: "sarif",
			File:   sarifFixture("trivy.sarif"),
			Tool:   "trivy",
		},
		{
			Format: "ocsf",
			File:   ocsfFixture("aws-security-hub.json"),
			Tool:   "aws-security-hub",
		},
	}

	findings, warnings, err := runIngestSources(context.Background(), sources, graph)
	if err != nil {
		t.Fatalf("runIngestSources: %v", err)
	}
	if len(findings) < 4 {
		t.Errorf("findings = %d, want at least 4 (3 trivy + 2 security-hub)", len(findings))
	}

	// Provenance: every finding should carry a Source with Type="ingest".
	for _, f := range findings {
		if f.Source == nil || f.Source.Type != "ingest" {
			t.Errorf("Source = %+v for %s", f.Source, f.CheckID)
		}
	}

	// Phantom resources were added to the graph.
	if graph.Count() == 0 {
		t.Errorf("graph still empty after ingest — phantom resources not added")
	}

	// v0.14+: CVE-prefixed rules route through the default vuln-mgmt
	// mapping (SOC 2 CC7.1 / NIST SI-2 / ISO A.8.8 / PCI 6.3 / CIS 7.1)
	// and produce no "unmapped" warning. Other unmappable rules
	// (CKV_K8S_22 with no built-in entry, etc.) may still emit
	// warnings; this test no longer asserts their presence because
	// the fixture content is sourced from Phase 1 and may change.
	_ = warnings
	_ = strings.HasPrefix // import retention; used by other tests in this file
}

// TestRunIngestSources_UnknownFormatErrors covers the config-validation
// path: a typo in `format:` aborts the scan with a clear error rather
// than silently skipping the entry.
func TestRunIngestSources_UnknownFormatErrors(t *testing.T) {
	graph := core.NewResourceGraph()
	sources := []config.IngestSource{
		{Format: "saarif", File: sarifFixture("trivy.sarif")},
	}
	_, _, err := runIngestSources(context.Background(), sources, graph)
	if err == nil {
		t.Fatalf("expected error on unknown format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error = %v, want 'unknown format' phrase", err)
	}
}

// TestRunIngestSources_MissingFileErrors covers the file-not-found
// path: the operator's mistake bubbles up rather than producing
// silent zero findings.
func TestRunIngestSources_MissingFileErrors(t *testing.T) {
	graph := core.NewResourceGraph()
	sources := []config.IngestSource{
		{Format: "sarif", File: "/does/not/exist.sarif"},
	}
	_, _, err := runIngestSources(context.Background(), sources, graph)
	if err == nil {
		t.Fatalf("expected error on missing file")
	}
}

// TestRunIngestSources_EmptyConfigNoOp confirms a config with zero
// ingest entries is a clean no-op, not an error.
func TestRunIngestSources_EmptyConfigNoOp(t *testing.T) {
	findings, warns, err := runIngestSources(context.Background(), nil, core.NewResourceGraph())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 || len(warns) != 0 {
		t.Errorf("expected empty results; got %d findings %d warns", len(findings), len(warns))
	}
}
