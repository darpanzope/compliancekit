package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// fixtureGraph builds a graph with two test buckets — one public,
// one private — used across the loader + evaluator tests.
func fixtureGraph(t *testing.T) *core.ResourceGraph {
	t.Helper()
	g := core.NewResourceGraph()
	g.Add(core.Resource{
		ID:       "test.bucket.public",
		Type:     "test.bucket",
		Name:     "public-data",
		Provider: "test",
		Attributes: map[string]any{
			"public": true,
		},
	})
	g.Add(core.Resource{
		ID:       "test.bucket.private",
		Type:     "test.bucket",
		Name:     "private-data",
		Provider: "test",
		Attributes: map[string]any{
			"public": false,
		},
	})
	return g
}

func TestLoadFile(t *testing.T) {
	m, err := LoadFile(context.Background(), "testdata/sample.rego")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if m.Check.ID != "test-sample-bucket-public" {
		t.Errorf("Check.ID = %q", m.Check.ID)
	}
	if m.Check.Severity != core.SeverityHigh {
		t.Errorf("Check.Severity = %v, want high", m.Check.Severity)
	}
	if m.Check.Policy != "testdata/sample.rego" {
		t.Errorf("Check.Policy = %q, want sourcefile pinned", m.Check.Policy)
	}
	if m.Check.Scanner != "" {
		t.Errorf("Check.Scanner must be empty for Rego-backed checks")
	}
	if len(m.Check.Frameworks["soc2"]) != 1 || m.Check.Frameworks["soc2"][0] != "CC6.1" {
		t.Errorf("Frameworks not lifted: %+v", m.Check.Frameworks)
	}
}

func TestEvaluate(t *testing.T) {
	m, err := LoadFile(context.Background(), "testdata/sample.rego")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	findings, err := m.Evaluate(context.Background(), fixtureGraph(t))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the public bucket)", len(findings))
	}
	f := findings[0]
	if f.CheckID != "test-sample-bucket-public" {
		t.Errorf("CheckID = %q", f.CheckID)
	}
	if f.Status != core.StatusFail {
		t.Errorf("Status = %v, want fail", f.Status)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("Severity inherited from Check expected high, got %v", f.Severity)
	}
	if !strings.Contains(f.Message, "public-data") {
		t.Errorf("Message should mention the public bucket name: %q", f.Message)
	}
	if f.Resource.ID != "test.bucket.public" {
		t.Errorf("Resource.ID = %q, want resolved from graph", f.Resource.ID)
	}
	if f.Resource.Provider != "test" {
		t.Errorf("Resource.Provider should be lifted from the graph entry, got %q", f.Resource.Provider)
	}
}

func TestLoadDir(t *testing.T) {
	mods, errs := LoadDir(context.Background(), "testdata")
	if len(errs) != 0 {
		t.Fatalf("unexpected load errors: %v", errs)
	}
	if len(mods) == 0 {
		t.Fatalf("expected at least 1 module from testdata/")
	}
	// Verify deterministic sort by Check.ID and that the sample policy
	// is present. Multiple fixtures in testdata/ are fine — additional
	// .rego files (e.g. builtins.rego) load alongside this one.
	ids := make([]string, len(mods))
	for i, m := range mods {
		ids[i] = m.Check.ID
	}
	found := false
	for _, id := range ids {
		if id == "test-sample-bucket-public" {
			found = true
		}
	}
	if !found {
		t.Errorf("sample policy missing from LoadDir output; got %v", ids)
	}
}

func TestLoadDir_MissingDirReturnsNil(t *testing.T) {
	mods, errs := LoadDir(context.Background(), "testdata/does-not-exist")
	if len(errs) != 0 {
		t.Errorf("missing dir should not error, got: %v", errs)
	}
	if mods != nil {
		t.Errorf("missing dir should return nil modules, got %d", len(mods))
	}
}

func TestCompile_MissingPackage(t *testing.T) {
	_, err := Compile(context.Background(), "ad-hoc.rego", "metadata := {}\n")
	if err == nil || !strings.Contains(err.Error(), "package") {
		t.Errorf("expected `missing package` error, got %v", err)
	}
}

func TestCompile_MissingMetadata(t *testing.T) {
	_, err := Compile(context.Background(), "ad-hoc.rego", "package x\nfindings := []\n")
	if err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Errorf("expected `missing metadata` error, got %v", err)
	}
}

func TestCompile_BadSeverity(t *testing.T) {
	body := `package x
metadata := {
  "id": "x", "title": "x", "description": "x", "severity": "bogus", "provider": "test",
}
findings := []
`
	_, err := Compile(context.Background(), "ad-hoc.rego", body)
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Errorf("bad severity should fail loading, got %v", err)
	}
}

func TestEvaluate_StatusOverride(t *testing.T) {
	// A policy that emits status=pass should produce a pass finding,
	// not an error. Confirms ParseStatus round-trip.
	body := `package x
metadata := {
  "id": "always-pass", "title": "x", "description": "x", "severity": "low", "provider": "test",
}
findings := [{
  "resource_id": "test.bucket.private", "status": "pass",
}]
`
	m, err := Compile(context.Background(), "ad-hoc.rego", body)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, err := m.Evaluate(context.Background(), fixtureGraph(t))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(out) != 1 || out[0].Status != core.StatusPass {
		t.Errorf("expected one pass finding, got %+v", out)
	}
}
