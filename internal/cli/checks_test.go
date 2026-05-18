package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"

	// Side-effect imports: these populate the default check registry
	// at test-binary init, mirroring what cmd/compliancekit/main.go
	// does in production. Without them every checks-list / checks-show
	// test would see an empty catalog.
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
	_ "github.com/darpanzope/compliancekit/internal/checks/linux"
)

// These tests use the package-default registry, which is populated at
// init by side-effect imports in cmd/compliancekit. Importing the
// check packages here pulls those inits into the test binary.

func TestChecksList_TableShowsAllChecks(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{format: "table"}); err != nil {
		t.Fatalf("runChecksList: %v", err)
	}
	out := buf.String()
	// Header row present.
	if !strings.Contains(out, "ID") || !strings.Contains(out, "SEVERITY") {
		t.Errorf("header missing from table output:\n%s", out)
	}
	// At least one check from each package shows up.
	for _, expected := range []string{
		"do-droplet-no-firewall",
		"linux-sshd-no-root-login",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %q in output, got:\n%s", expected, out)
		}
	}
}

func TestChecksList_JSONIsParseable(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{format: "json"}); err != nil {
		t.Fatalf("runChecksList json: %v", err)
	}
	var arr []compliancekit.Check
	if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(arr) == 0 {
		t.Error("JSON output is empty array; expected at least one registered check")
	}
}

func TestChecksList_CSVHasHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{format: "csv"}); err != nil {
		t.Fatalf("runChecksList csv: %v", err)
	}
	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("expected header + at least one row, got %d records", len(records))
	}
	header := records[0]
	wantHeader := []string{"id", "severity", "provider", "service", "title", "frameworks"}
	for i, h := range wantHeader {
		if header[i] != h {
			t.Errorf("header[%d] = %q, want %q", i, header[i], h)
		}
	}
}

func TestChecksList_UnknownFormatFails(t *testing.T) {
	var buf bytes.Buffer
	err := runChecksList(&buf, checksListOptions{format: "toml"})
	if err == nil {
		t.Error("expected error for unknown --format")
	}
}

func TestChecksList_FilterByFramework(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{framework: "soc2"}); err != nil {
		t.Fatalf("runChecksList: %v", err)
	}
	// Should still include checks that map to soc2 -- our DO and Linux
	// checks all do.
	out := buf.String()
	if !strings.Contains(out, "do-droplet-no-firewall") {
		t.Errorf("expected soc2-mapped check in framework=soc2 output")
	}
}

func TestChecksList_FilterByProvider(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{provider: "linux"}); err != nil {
		t.Fatalf("runChecksList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "linux-sshd-no-root-login") {
		t.Error("linux check missing from provider=linux output")
	}
	if strings.Contains(out, "do-droplet-no-firewall") {
		t.Error("DO check should not appear in provider=linux output")
	}
}

func TestChecksList_FilterBySeverity(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksList(&buf, checksListOptions{severity: "high"}); err != nil {
		t.Fatalf("runChecksList: %v", err)
	}
	out := buf.String()
	// High-severity checks present.
	if !strings.Contains(out, "do-droplet-no-firewall") {
		t.Error("high-severity DO check missing")
	}
	// Low-severity check should be filtered out.
	if strings.Contains(out, "do-droplet-no-tags") {
		t.Error("low-severity check should be filtered out at --severity=high")
	}
}

func TestChecksList_FilterBySeverity_InvalidErrors(t *testing.T) {
	var buf bytes.Buffer
	err := runChecksList(&buf, checksListOptions{severity: "ohno"})
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestChecksShow_RealCheck(t *testing.T) {
	var buf bytes.Buffer
	if err := runChecksShow(&buf, "do-droplet-no-firewall"); err != nil {
		t.Fatalf("runChecksShow: %v", err)
	}
	out := buf.String()
	wantSubstrings := []string{
		"do-droplet-no-firewall",
		"Title:",
		"Severity:",
		"Description:",
		"Remediation:",
		"Framework mappings:",
		"soc2",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("expected %q in show output, got:\n%s", s, out)
		}
	}
}

func TestChecksShow_NotFound(t *testing.T) {
	var buf bytes.Buffer
	err := runChecksShow(&buf, "no-such-check")
	if err == nil {
		t.Error("expected error for unknown check id")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error should mention 'not registered', got: %v", err)
	}
}

func TestIndentBlock(t *testing.T) {
	got := indentBlock("line1\nline2\n")
	want := "  line1\n  line2"
	if got != want {
		t.Errorf("indentBlock = %q, want %q", got, want)
	}
}
