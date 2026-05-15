package oscal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/frameworks"
	"github.com/darpanzope/compliancekit/internal/ingest"
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
	got, ok := ingest.Default.Lookup("oscal-catalog")
	if !ok {
		t.Fatalf("oscal-catalog adapter not registered")
	}
	if got.Format() != "oscal-catalog" {
		t.Errorf("Format = %q", got.Format())
	}
}

func TestIngest_JSON(t *testing.T) {
	t.Cleanup(func() { frameworks.Unregister("oscal.acme-internal-security-baseline") })

	a := adapter{}
	r, err := a.Ingest(context.Background(), mustOpen(t, "mini-catalog.json"), ingest.Options{
		Provenance: ingest.Provenance{File: "testdata/mini-catalog.json"},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 (catalog ingest is structural, not finding-shaped)", len(r.Findings))
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "registered OSCAL framework") {
		t.Errorf("Warnings = %v", r.Warnings)
	}

	fw, ok := frameworks.Get("oscal.acme-internal-security-baseline")
	if !ok {
		t.Fatalf("framework not registered")
	}
	if fw.Name != "Acme Internal Security Baseline" {
		t.Errorf("Name = %q", fw.Name)
	}
	if fw.Version != "2026.1" {
		t.Errorf("Version = %q", fw.Version)
	}
	if len(fw.Controls) != 3 {
		t.Errorf("Controls = %d, want 3", len(fw.Controls))
	}
	if c, ok := fw.Controls["ac-1"]; !ok {
		t.Errorf("ac-1 missing")
	} else {
		if c.Name != "Access Control Policy and Procedures" {
			t.Errorf("ac-1.Name = %q", c.Name)
		}
		if c.Family != "AC" {
			t.Errorf("ac-1.Family = %q, want AC", c.Family)
		}
		if !c.HasTag("low-impact") {
			t.Errorf("ac-1.Tags = %v, want low-impact present", c.Tags)
		}
		if len(c.References) == 0 || c.References[0] != "NIST 800-53 AC-1" {
			t.Errorf("ac-1.References = %v", c.References)
		}
		if !strings.Contains(c.Description, "access control policy") {
			t.Errorf("ac-1.Description = %q", c.Description)
		}
	}
}

func TestIngest_YAML(t *testing.T) {
	t.Cleanup(func() { frameworks.Unregister("oscal.acme-yaml-catalog") })

	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "mini-catalog.yaml"), ingest.Options{
		Provenance: ingest.Provenance{File: "testdata/mini-catalog.yaml"},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("Warnings = %v", r.Warnings)
	}

	fw, ok := frameworks.Get("oscal.acme-yaml-catalog")
	if !ok {
		t.Fatalf("framework not registered")
	}
	if len(fw.Controls) != 2 {
		t.Errorf("Controls = %d, want 2", len(fw.Controls))
	}
	if _, ok := fw.Controls["sc-7"]; !ok {
		t.Errorf("sc-7 missing")
	}
}

func TestIngest_XML(t *testing.T) {
	t.Cleanup(func() { frameworks.Unregister("oscal.acme-xml-catalog") })

	r, err := adapter{}.Ingest(context.Background(), mustOpen(t, "mini-catalog.xml"), ingest.Options{
		Provenance: ingest.Provenance{File: "testdata/mini-catalog.xml"},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("Warnings = %v", r.Warnings)
	}

	fw, ok := frameworks.Get("oscal.acme-xml-catalog")
	if !ok {
		t.Fatalf("framework not registered")
	}
	if len(fw.Controls) != 2 {
		t.Errorf("Controls = %d, want 2", len(fw.Controls))
	}
	if c, ok := fw.Controls["ia-2"]; !ok || !strings.Contains(c.Description, "Uniquely identify") {
		t.Errorf("ia-2 missing or description wrong: %+v", c)
	}
}

func TestKebab(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Acme Security Baseline", "acme-security-baseline"},
		{"NIST 800-53 r5", "nist-800-53-r5"},
		{"  Padded  ", "padded"},
		{"!!!", "imported"},
		{"", "imported"},
	}
	for _, c := range cases {
		if got := kebab(c.in); got != c.want {
			t.Errorf("kebab(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIngest_EmptyError(t *testing.T) {
	_, err := adapter{}.Ingest(context.Background(), strings.NewReader(""), ingest.Options{})
	if err == nil {
		t.Fatalf("expected error on empty payload")
	}
}

func TestRuntimeRegistrationVisibleViaAll(t *testing.T) {
	t.Cleanup(func() { frameworks.Unregister("oscal.runtime-test") })

	if err := frameworks.Register(&frameworks.Framework{
		ID:   "oscal.runtime-test",
		Name: "Runtime Test",
		Controls: map[string]frameworks.Control{
			"r1": {ID: "r1", Name: "rule 1"},
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	all, err := frameworks.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if _, ok := all["oscal.runtime-test"]; !ok {
		t.Fatalf("oscal.runtime-test not visible via All()")
	}
	if _, ok := all["soc2"]; !ok {
		t.Fatalf("embedded soc2 not visible alongside runtime entry")
	}
}
