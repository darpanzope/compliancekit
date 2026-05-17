package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/policy"
)

// fixtureJSON is the shape `compliancekit policy test` expects on disk.
const fixtureJSON = `[
  {
    "id": "test.bucket.public",
    "type": "test.bucket",
    "name": "public-data",
    "provider": "test",
    "attributes": {"public": true}
  },
  {
    "id": "test.bucket.private",
    "type": "test.bucket",
    "name": "private-data",
    "provider": "test",
    "attributes": {"public": false}
  }
]`

func TestPolicyTest_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixturePath, []byte(fixtureJSON), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	if err := runPolicyTest(context.Background(), &out, fixturePath, "../policy/testdata/sample.rego", "json"); err != nil {
		t.Fatalf("runPolicyTest: %v", err)
	}
	var findings []core.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out.String())
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the public bucket); got\n%+v", len(findings), findings)
	}
	if findings[0].Resource.ID != "test.bucket.public" {
		t.Errorf("Resource.ID = %q", findings[0].Resource.ID)
	}
}

func TestPolicyTest_TableOutput(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixturePath, []byte(fixtureJSON), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	if err := runPolicyTest(context.Background(), &out, fixturePath, "../policy/testdata/sample.rego", "table"); err != nil {
		t.Fatalf("runPolicyTest: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "1 finding(s)") {
		t.Errorf("missing finding count: %s", s)
	}
	if !strings.Contains(s, "test.bucket.public") {
		t.Errorf("missing resource ID: %s", s)
	}
}

func TestPolicyValidate_OK(t *testing.T) {
	t.Cleanup(policy.Reset)
	var out bytes.Buffer
	if err := runPolicyValidate(context.Background(), &out, "../policy/testdata"); err != nil {
		t.Fatalf("validate: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Loaded 2 policy module(s)") {
		t.Errorf("expected 2 modules in summary; got\n%s", out.String())
	}
}

func TestPolicyFmt_Idempotent(t *testing.T) {
	// Property: running fmt twice in a row produces no further
	// changes on the second run. (We can't assume the source
	// fixture matches opa fmt's canonical form, since OPA's
	// formatter may evolve across versions.)
	dir := t.TempDir()
	target := filepath.Join(dir, "sample.rego")
	body, err := os.ReadFile("../policy/testdata/sample.rego")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(target, body, 0o644); err != nil {
		t.Fatalf("write copy: %v", err)
	}
	// First run: may or may not rewrite.
	var firstOut bytes.Buffer
	if err := runPolicyFmt(&firstOut, []string{target}, false); err != nil {
		t.Fatalf("fmt first run: %v\n%s", err, firstOut.String())
	}
	// Second run: must report zero rewrites.
	var secondOut bytes.Buffer
	if err := runPolicyFmt(&secondOut, []string{target}, false); err != nil {
		t.Fatalf("fmt second run: %v\n%s", err, secondOut.String())
	}
	if !strings.Contains(secondOut.String(), "0 file(s) reformatted") {
		t.Errorf("fmt is not idempotent — second run still rewrites:\n%s", secondOut.String())
	}
}

func TestPolicyFmt_CheckFlagDetectsDirty(t *testing.T) {
	// Write a deliberately-ugly policy and confirm --check reports it
	// would change. The exit-code behavior is asserted via the
	// returned error.
	dir := t.TempDir()
	ugly := `package x
metadata    :=   {"id":"x","title":"x","description":"x","severity":"low","provider":"test"}
findings:=[]
`
	target := filepath.Join(dir, "ugly.rego")
	if err := os.WriteFile(target, []byte(ugly), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out bytes.Buffer
	err := runPolicyFmt(&out, []string{target}, true)
	if err == nil {
		t.Errorf("--check should exit non-zero on dirty file")
	}
	if !strings.Contains(out.String(), "would reformat") {
		t.Errorf("expected `would reformat` message; got\n%s", out.String())
	}
}
