package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

func TestScaffold_RegoDefault(t *testing.T) {
	dir := t.TempDir()
	id := "demo-pack"
	dest := filepath.Join(dir, id)
	if err := os.MkdirAll(dest, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := scaffold(dest, id, plugin.KindCheck, false, "alice"); err != nil {
		t.Fatalf("scaffold: %v", err)
	}

	for _, want := range []string{"manifest.yaml", "README.md", "rego/" + id + ".rego"} {
		path := filepath.Join(dest, want)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s: %v", path, err)
		}
	}

	body, err := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m plugin.Manifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("manifest invalid: %v", err)
	}
	if m.Name != id {
		t.Errorf("manifest.name=%q want %q", m.Name, id)
	}
	if len(m.RegoPacks) != 1 {
		t.Errorf("manifest.rego_packs=%v, want 1 entry", m.RegoPacks)
	}
	if m.Entrypoint != "" {
		t.Errorf("rego-only plugin should have no entrypoint, got %q", m.Entrypoint)
	}
}

func TestScaffold_GoSubprocess(t *testing.T) {
	dir := t.TempDir()
	id := "go-check"
	dest := filepath.Join(dir, id)
	if err := os.MkdirAll(dest, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := scaffold(dest, id, plugin.KindCheck, true, "carol"); err != nil {
		t.Fatalf("scaffold: %v", err)
	}
	for _, want := range []string{"manifest.yaml", "cmd/" + id + "/main.go"} {
		if _, err := os.Stat(filepath.Join(dest, want)); err != nil {
			t.Errorf("expected %s: %v", want, err)
		}
	}
	body, _ := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if !strings.Contains(string(body), "entrypoint: ./bin/"+id) {
		t.Errorf("Go scaffold missing entrypoint line: %s", body)
	}
}

func TestIDPatternEnforced(t *testing.T) {
	bad := []string{"", "X", "-leading", "trailing-", "has space", "UpperCase", "a"}
	good := []string{"my-check", "aws.iam.mfa", "hello-world-2"}
	for _, id := range bad {
		if idPattern.MatchString(id) {
			t.Errorf("bad id %q should not match", id)
		}
	}
	for _, id := range good {
		if !idPattern.MatchString(id) {
			t.Errorf("good id %q should match", id)
		}
	}
}

func TestRegoPackageID(t *testing.T) {
	if got := regoPackageID("aws-iam-mfa.strict"); got != "aws_iam_mfa_strict" {
		t.Errorf("regoPackageID = %q want aws_iam_mfa_strict", got)
	}
}
