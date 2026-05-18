package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// TestWriteAssessmentResultsOSCAL exercises the v0.13 OSCAL AR emit
// path: given a couple of synthetic findings + a tailoring entry,
// the generated assessment-results.oscal.json should be a well-formed
// OSCAL AR v1.1 document, include one finding per (finding, control)
// pair, include the tailoring justification as a separate finding
// targeting the scoped-out control, and use deterministic UUIDs so
// re-runs produce identical bytes.
func TestWriteAssessmentResultsOSCAL(t *testing.T) {
	// Pick a real registered check so controlIDsForFinding returns
	// at least one (framework, control) pair.
	registered := compliancekit.RegisteredChecks()
	if len(registered) == 0 {
		t.Skip("no checks registered, cannot test OSCAL AR projection")
	}
	check := registered[0]

	findings := []compliancekit.Finding{
		{
			CheckID:  check.ID,
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{ID: "do://droplet/web-prod-3", Type: "do.droplet", Name: "web-prod-3"},
			Message:  "Droplet exposes ssh on public IPv4",
		},
		{
			CheckID:  check.ID,
			Status:   compliancekit.StatusPass, // pass findings must NOT appear in AR
			Severity: compliancekit.SeverityLow,
			Resource: compliancekit.ResourceRef{ID: "do://droplet/web-prod-4", Type: "do.droplet", Name: "web-prod-4"},
		},
	}

	tailoring, err := frameworks.NewTailoring([]frameworks.TailoringRule{
		{Framework: "soc2", Control: "P1.1", Justification: "Privacy out of scope"},
	})
	if err != nil {
		t.Fatalf("NewTailoring: %v", err)
	}

	dir := t.TempDir()
	opts := Options{
		OutDir:    dir,
		Period:    "2026-Q2",
		Generated: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Tailoring: tailoring,
	}

	path, err := writeAssessmentResultsOSCAL(dir, findings, opts)
	if err != nil {
		t.Fatalf("writeAssessmentResultsOSCAL: %v", err)
	}
	if !strings.HasSuffix(path, "assessment-results.oscal.json") {
		t.Fatalf("path = %q", path)
	}

	// Round-trip the file as JSON, then re-marshal and compare for
	// stability across re-runs.
	body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // path is from temp dir
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var doc arDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode oscal-ar: %v", err)
	}

	if doc.AssessmentResults.UUID == "" {
		t.Errorf("AR UUID empty")
	}
	if !strings.Contains(doc.AssessmentResults.UUID, "-") || len(doc.AssessmentResults.UUID) != 36 {
		t.Errorf("AR UUID %q not in UUID-shape", doc.AssessmentResults.UUID)
	}
	if doc.AssessmentResults.Metadata.OSCALVersion != oscalVersion {
		t.Errorf("OSCALVersion = %q", doc.AssessmentResults.Metadata.OSCALVersion)
	}
	if len(doc.AssessmentResults.Results) != 1 {
		t.Fatalf("Results = %d, want 1", len(doc.AssessmentResults.Results))
	}

	res := doc.AssessmentResults.Results[0]

	// Findings: actionable finding per mapped control, + one tailoring entry.
	if len(res.Findings) == 0 {
		t.Fatalf("Findings empty")
	}

	var sawTailoringFinding, sawActionableFinding bool
	for _, fnd := range res.Findings {
		for _, p := range fnd.Props {
			if p.Name == "compliancekit-tailored" && p.Value == "true" {
				sawTailoringFinding = true
			}
			if p.Name == "compliancekit-status" && p.Value == string(compliancekit.StatusFail) {
				sawActionableFinding = true
			}
		}
	}
	if !sawTailoringFinding {
		t.Errorf("missing tailoring finding in AR")
	}
	if !sawActionableFinding {
		t.Errorf("missing actionable finding in AR")
	}

	// Reviewed-controls must enumerate every (framework:control) targeted.
	if len(res.ReviewedControls.ControlSelections) == 0 {
		t.Fatalf("ReviewedControls empty")
	}
	sawTailoringCtrl := false
	for _, sel := range res.ReviewedControls.ControlSelections {
		for _, inc := range sel.IncludeControls {
			if inc.ControlID == "soc2:P1.1" {
				sawTailoringCtrl = true
			}
		}
	}
	if !sawTailoringCtrl {
		t.Errorf("ReviewedControls missing tailored soc2:P1.1")
	}

	// Re-generate with the same input — UUIDs must match byte-for-byte.
	rerun := buildAssessmentResults(findings, opts)
	if rerun.AssessmentResults.UUID != doc.AssessmentResults.UUID {
		t.Errorf("non-deterministic AR UUID across runs: %q vs %q",
			doc.AssessmentResults.UUID, rerun.AssessmentResults.UUID)
	}
}

func TestUUIDFromContent(t *testing.T) {
	cases := [][]string{
		{"a", "b"},
		{"alpha", "beta", "gamma"},
		{""},
	}
	seen := map[string]bool{}
	for _, in := range cases {
		got := uuidFromContent(in...)
		if len(got) != 36 {
			t.Errorf("uuidFromContent(%v) length = %d, want 36", in, len(got))
		}
		if got[14] != '5' { // version 5
			t.Errorf("uuidFromContent(%v) = %q, version digit not 5", in, got)
		}
		if seen[got] {
			t.Errorf("duplicate UUID across distinct inputs: %s", got)
		}
		seen[got] = true
	}

	// Stability: same input → same UUID.
	first := uuidFromContent("x", "y")
	second := uuidFromContent("x", "y")
	if first != second {
		t.Errorf("non-deterministic: %s vs %s", first, second)
	}
}
