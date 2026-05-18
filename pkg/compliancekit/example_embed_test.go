//go:build external

// This file is the v1.0 "external embedder" contract test. It builds
// only under -tags=external (default test runs skip it) and is
// written from the perspective of a downstream consumer who imports
// pkg/compliancekit by its public path and uses ONLY exported
// identifiers — package compliancekit_test, not compliancekit, so
// the test cannot accidentally lean on package-private helpers.
//
// If a refactor inside pkg/compliancekit accidentally narrows the
// public surface (e.g. drops an exported method, breaks a constructor
// signature), this test fails to compile — catching the regression
// before it ships, complementing the api.txt diff gate which catches
// it during PR review.
//
// CI runs:  go test -tags=external ./pkg/compliancekit/...
// Locally:  make test-external

package compliancekit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// TestEmbed_ScanRoundtrip walks the canonical embedding shape: build
// a ResourceGraph, register a check on a fresh Registry, run the
// check via the registered function, and verify the produced Finding
// round-trips through Fingerprint + JSON without losing identity.
//
// This is the smallest end-to-end thing an embedder can do with the
// v1.0 surface alone (no internal/ imports), so it doubles as the
// embedding "hello world" sample.
func TestEmbed_ScanRoundtrip(t *testing.T) {
	// 1. Build the graph of resources to evaluate.
	g := compliancekit.NewResourceGraph()
	g.Add(compliancekit.Resource{
		ID:       "linux.host.web-01",
		Type:     "linux.host",
		Name:     "web-01",
		Provider: "linux",
		Attributes: map[string]any{
			"ssh_password_auth": true,
		},
	})
	g.Add(compliancekit.Resource{
		ID:       "linux.host.web-02",
		Type:     "linux.host",
		Name:     "web-02",
		Provider: "linux",
		Attributes: map[string]any{
			"ssh_password_auth": false,
		},
	})

	// 2. Construct an isolated Registry and register one check.
	//    Using NewRegistry() (not the package-global default) is the
	//    embedder-friendly pattern — no init-time side-effects.
	reg := compliancekit.NewRegistry()
	check := compliancekit.Check{
		ID:          "ssh-password-auth-disabled",
		Title:       "SSH password authentication must be disabled",
		Severity:    compliancekit.SeverityHigh,
		Provider:    "linux",
		Description: "Password auth enables credential-stuffing.",
		Remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd.",
	}
	reg.Register(check, func(_ context.Context, graph *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
		var out []compliancekit.Finding
		for _, r := range graph.ByType("linux.host") {
			status := compliancekit.StatusPass
			msg := "ssh password auth disabled"
			if r.AttrBool("ssh_password_auth") {
				status = compliancekit.StatusFail
				msg = "ssh password auth enabled"
			}
			out = append(out, compliancekit.Finding{
				CheckID:  check.ID,
				Status:   status,
				Severity: check.Severity,
				Resource: r.Ref(),
				Message:  msg,
			})
		}
		return out, nil
	})

	// 3. Run every registered check against the graph.
	var findings []compliancekit.Finding
	for _, c := range reg.Checks() {
		fn, ok := reg.Get(c.ID)
		if !ok {
			t.Fatalf("Registry.Get(%q) missed a check the Checks() list claimed", c.ID)
		}
		got, err := fn(context.Background(), g)
		if err != nil {
			t.Fatalf("check %q evaluation: %v", c.ID, err)
		}
		findings = append(findings, got...)
	}

	// 4. Contract assertions.
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per host)", len(findings))
	}

	var fail, pass int
	for _, f := range findings {
		switch f.Status {
		case compliancekit.StatusFail:
			fail++
		case compliancekit.StatusPass:
			pass++
		}
		if f.Fingerprint() == "" {
			t.Errorf("Fingerprint() returned empty for %+v", f)
		}
		if !f.IsNative() {
			t.Errorf("IsNative() = false for engine-produced finding; want true")
		}
	}
	if fail != 1 || pass != 1 {
		t.Errorf("status split = %d fail / %d pass; want 1 / 1", fail, pass)
	}

	// 5. JSON round-trip — proves the wire shape is stable for
	//    downstream consumers that serialize findings to disk.
	b, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("Finding marshal: %v", err)
	}
	var decoded compliancekit.Finding
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Finding unmarshal: %v", err)
	}
	if decoded.CheckID != findings[0].CheckID {
		t.Errorf("CheckID lost in round-trip: got %q, want %q",
			decoded.CheckID, findings[0].CheckID)
	}
	if decoded.Severity != findings[0].Severity {
		t.Errorf("Severity lost in round-trip: got %s, want %s",
			decoded.Severity, findings[0].Severity)
	}
}

// TestEmbed_GraphQuery exercises the Query DSL from external code —
// proves the expression syntax + the public method are both usable
// without reaching into internal helpers.
func TestEmbed_GraphQuery(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	for i, host := range []struct {
		name  string
		prod  bool
		ports []string
	}{
		{"web-01", true, []string{"http", "https"}},
		{"web-02", true, []string{"http"}},
		{"staging", false, []string{"http"}},
	} {
		tags := []string{"linux"}
		if host.prod {
			tags = append(tags, "prod")
		}
		g.Add(compliancekit.Resource{
			ID:       compliancekitTestHostID(i),
			Type:     "linux.host",
			Name:     host.name,
			Provider: "linux",
			Tags:     tags,
		})
	}

	prod, err := g.Query(`type = "linux.host" AND tag CONTAINS "prod"`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(prod) != 2 {
		t.Errorf("prod count = %d, want 2", len(prod))
	}

	notStaging, err := g.Query(`type = "linux.host" AND name != "staging"`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(notStaging) != 2 {
		t.Errorf("non-staging count = %d, want 2", len(notStaging))
	}
}

// TestEmbed_FrameworkCatalog instantiates a Framework + Control set
// the way an embedder building a custom catalog would: directly,
// without going through internal/frameworks' embedded YAML loader.
func TestEmbed_FrameworkCatalog(t *testing.T) {
	fw := &compliancekit.Framework{
		ID:      "company-internal",
		Name:    "Internal compliance overlay",
		Version: "2026.05",
		Controls: map[string]compliancekit.Control{
			"DC-1": {Name: "Data classification labels exist", Tags: []string{"required"}},
			"DC-2": {Name: "Backups are encrypted at rest", Tags: []string{"required"}},
		},
	}
	if fw.IsThreatModel() {
		t.Error("compliance-category framework should not report as threat model")
	}
	if !fw.Controls["DC-1"].HasTag("required") {
		t.Error("Control.HasTag should match (case-insensitive)")
	}
	if !fw.Controls["DC-1"].HasTag("REQUIRED") {
		t.Error("Control.HasTag should be case-insensitive")
	}
}

// compliancekitTestHostID returns a stable test ID for the i'th host.
// Named with the project prefix to avoid colliding with any future
// helper in the public package (since this file imports the package
// from the outside, no internal helpers are reachable anyway).
func compliancekitTestHostID(i int) string {
	return "linux.host." + string(rune('a'+i))
}
