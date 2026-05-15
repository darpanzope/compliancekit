package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/frameworks"
)

// TestWriteProfileOSCAL exercises the v0.13 OSCAL Profile emit:
// given a Result covering several frameworks plus tailoring rules,
// the generated profile.oscal.json should have one import per
// framework with include-all + per-framework exclude-controls
// reflecting the tailored scope-outs.
func TestWriteProfileOSCAL(t *testing.T) {
	tailoring, err := frameworks.NewTailoring([]frameworks.TailoringRule{
		{Framework: "soc2", Control: "P1.1", Justification: "Privacy out of scope"},
		{Framework: "soc2", Control: "P2.1", Justification: "Privacy out of scope"},
		{Framework: "pci-dss-v4", Control: "10.6.1", Justification: "No CDE"},
	})
	if err != nil {
		t.Fatalf("NewTailoring: %v", err)
	}

	res := &Result{
		FrameworkResults: []FrameworkResult{
			{FrameworkID: "soc2", FrameworkName: "SOC 2 Trust Services Criteria"},
			{FrameworkID: "iso27001", FrameworkName: "ISO/IEC 27001 Annex A"},
		},
	}
	opts := Options{
		Period:    "2026-Q2",
		Generated: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		Tailoring: tailoring,
	}

	dir := t.TempDir()
	path, err := writeProfileOSCAL(dir, res, opts)
	if err != nil {
		t.Fatalf("writeProfileOSCAL: %v", err)
	}
	if !strings.HasSuffix(path, "profile.oscal.json") {
		t.Fatalf("path = %q", path)
	}

	body, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc profileDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode profile: %v", err)
	}

	// One import per framework (soc2, iso27001, pci-dss-v4 — pci was
	// tailored even though no FrameworkResults entry exists; that's
	// the "still emit so the audit knows we scoped X out" path).
	if len(doc.Profile.Imports) != 3 {
		t.Fatalf("Imports = %d, want 3 (soc2, iso27001, pci-dss-v4)", len(doc.Profile.Imports))
	}

	byHref := map[string]profileImport{}
	for _, imp := range doc.Profile.Imports {
		byHref[imp.Href] = imp
	}

	soc2 := byHref[catalogHrefBase+"soc2.yaml"]
	if soc2.IncludeAll == nil {
		t.Errorf("soc2 IncludeAll nil")
	}
	if len(soc2.ExcludeControls) != 1 || len(soc2.ExcludeControls[0].WithIDs) != 2 {
		t.Errorf("soc2 ExcludeControls = %+v, want 2 ids (P1.1, P2.1)", soc2.ExcludeControls)
	}

	iso := byHref[catalogHrefBase+"iso27001.yaml"]
	if iso.IncludeAll == nil {
		t.Errorf("iso27001 IncludeAll nil")
	}
	if len(iso.ExcludeControls) != 0 {
		t.Errorf("iso27001 ExcludeControls = %+v, want zero (no tailoring on this framework)", iso.ExcludeControls)
	}

	pci := byHref[catalogHrefBase+"pci-dss-v4.yaml"]
	if len(pci.ExcludeControls) == 0 || pci.ExcludeControls[0].WithIDs[0] != "10.6.1" {
		t.Errorf("pci-dss-v4 ExcludeControls = %+v, want 10.6.1", pci.ExcludeControls)
	}

	// UUID determinism: same Result + Options → same UUID.
	rerun := buildProfile(res, opts)
	if rerun.Profile.UUID != doc.Profile.UUID {
		t.Errorf("non-deterministic profile UUID: %q vs %q", doc.Profile.UUID, rerun.Profile.UUID)
	}
}

func TestBuildProfile_NoTailoring(t *testing.T) {
	// Result with one framework, no tailoring. Profile should still
	// emit an import for that framework with include-all and no
	// exclude-controls.
	res := &Result{
		FrameworkResults: []FrameworkResult{{FrameworkID: "cis-v8", FrameworkName: "CIS Controls v8"}},
	}
	opts := Options{Period: "test", Generated: time.Now().UTC()}
	doc := buildProfile(res, opts)
	if len(doc.Profile.Imports) != 1 {
		t.Fatalf("Imports = %d", len(doc.Profile.Imports))
	}
	if doc.Profile.Imports[0].IncludeAll == nil {
		t.Errorf("IncludeAll nil")
	}
	if len(doc.Profile.Imports[0].ExcludeControls) != 0 {
		t.Errorf("ExcludeControls = %+v", doc.Profile.Imports[0].ExcludeControls)
	}
}
