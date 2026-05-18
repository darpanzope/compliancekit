package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// stubGoCheck registers a Go-backed check directly with
// compliancekit.DefaultRegistry so the conflict-detection tests can assert
// RegisterModule refuses to overwrite.
func stubGoCheck(id string) {
	compliancekit.Register(compliancekit.Check{
		ID: id, Title: "stub", Severity: compliancekit.SeverityLow, Provider: "test",
		Description: "stub", Scanner: "stub",
	}, func(_ context.Context, _ *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		return nil, nil
	})
}

func TestRegisterModule_HappyPath(t *testing.T) {
	t.Cleanup(Reset)
	m, err := LoadFile(context.Background(), "testdata/sample.rego")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := RegisterModule(m); err != nil {
		t.Fatalf("RegisterModule: %v", err)
	}
	// Mirrored into compliancekit.DefaultRegistry?
	if _, ok := compliancekit.LookupCheck("test-sample-bucket-public"); !ok {
		t.Errorf("module not mirrored into compliancekit.DefaultRegistry")
	}
	// Lookup returns the policy package's metadata?
	got := Lookup("test-sample-bucket-public")
	if got == nil {
		t.Fatalf("Lookup returned nil")
	}
	if got.SourcePath != "testdata/sample.rego" {
		t.Errorf("SourcePath = %q", got.SourcePath)
	}
}

func TestRegisterModule_ConflictWithGoCheck(t *testing.T) {
	t.Cleanup(Reset)
	id := "test-conflict-policy"

	// Pre-register a Go check under the same ID.
	stubGoCheck(id)
	t.Cleanup(func() { compliancekit.Unregister(id) })

	// Build a Rego module with the same ID — must refuse.
	body := `package x
metadata := {"id":"` + id + `","title":"x","description":"x","severity":"low","provider":"test"}
findings := []
`
	m, err := Compile(context.Background(), "conflict.rego", body)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	err = RegisterModule(m)
	if err == nil {
		t.Fatalf("expected duplicate-ID error")
	}
	if !strings.Contains(err.Error(), "already registered by Go") {
		t.Errorf("error message should call out the existing Go-backed check: %v", err)
	}
}

func TestRegisterModule_ConflictBetweenTwoRegoModules(t *testing.T) {
	t.Cleanup(Reset)
	body := func(id string) string {
		return `package p
metadata := {"id":"` + id + `","title":"x","description":"x","severity":"low","provider":"test"}
findings := []
`
	}
	id := "test-dup-rego"

	m1, _ := Compile(context.Background(), "first.rego", body(id))
	if err := RegisterModule(m1); err != nil {
		t.Fatalf("first RegisterModule: %v", err)
	}

	m2, _ := Compile(context.Background(), "second.rego", body(id))
	err := RegisterModule(m2)
	if err == nil {
		t.Fatalf("expected duplicate-ID error")
	}
	if !strings.Contains(err.Error(), "Rego (first.rego)") {
		t.Errorf("error should cite the earlier Rego source path; got: %v", err)
	}
}

func TestRegisteredIDs_SortedAndScopedToRego(t *testing.T) {
	t.Cleanup(Reset)
	for _, id := range []string{"check-z", "check-a", "check-m"} {
		body := `package p
metadata := {"id":"` + id + `","title":"x","description":"x","severity":"low","provider":"test"}
findings := []
`
		m, err := Compile(context.Background(), id+".rego", body)
		if err != nil {
			t.Fatalf("Compile(%s): %v", id, err)
		}
		if err := RegisterModule(m); err != nil {
			t.Fatalf("Register(%s): %v", id, err)
		}
	}
	got := RegisteredIDs()
	if len(got) != 3 || got[0] != "check-a" || got[1] != "check-m" || got[2] != "check-z" {
		t.Errorf("RegisteredIDs = %v; want sorted [check-a check-m check-z]", got)
	}
}

func TestLoadAndRegisterDir_SkipsTestFiles(t *testing.T) {
	t.Cleanup(Reset)
	// testdata has sample.rego + builtins.rego, both non-_test files.
	registered, err := LoadAndRegisterDir(context.Background(), "testdata")
	if err != nil {
		t.Fatalf("LoadAndRegisterDir: %v", err)
	}
	if registered != 2 {
		t.Errorf("registered = %d, want 2 (sample + builtins)", registered)
	}
}
