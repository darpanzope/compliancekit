package bash

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestRegistryCoverage_Linux(t *testing.T) {
	cases := []string{
		"linux-sshd-no-root-login",
		"linux-sshd-no-password-auth",
		"linux-firewall-active",
		"linux-aslr-enabled",
		"linux-no-source-routing",
		"linux-passwd-perms",
		"linux-shadow-perms",
		"linux-auditd-running",
		"linux-journald-persistent",
		"linux-uid-zero-only-root",
		"linux-no-empty-passwords",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatBash {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no bash strategy", id)
		}
	}
}

func TestWildcardFallback(t *testing.T) {
	// An unregistered CheckID should resolve via the wildcard
	// strategy in this package.
	f := compliancekit.Finding{
		CheckID:  "completely-unknown-check",
		Resource: compliancekit.ResourceRef{ID: "weird-resource"},
		Severity: compliancekit.SeverityMedium,
		Message:  "I am a finding without a strategy",
	}
	s, err := remediate.Default.Render(f, remediate.FormatBash)
	if err != nil {
		t.Fatalf("wildcard render: %v", err)
	}
	if s.Risk != remediate.RiskManual {
		t.Errorf("wildcard Risk = %v, want manual", s.Risk)
	}
	for _, want := range []string{
		"completely-unknown-check",
		"weird-resource",
		"I am a finding without a strategy",
		"POA&M",
	} {
		if !strings.Contains(s.Content, want) {
			t.Errorf("wildcard missing %q in:\n%s", want, s.Content)
		}
	}
}

func TestRenderSSHDRootLogin(t *testing.T) {
	f := compliancekit.Finding{CheckID: "linux-sshd-no-root-login"}
	s, err := remediate.Default.Render(f, remediate.FormatBash)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "PermitRootLogin no") {
		t.Errorf("missing PermitRootLogin no: %s", s.Content)
	}
	if s.RollbackCmd == "" {
		t.Errorf("rollback should be populated")
	}
}
