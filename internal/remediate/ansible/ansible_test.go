package ansible

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"linux-sshd-no-root-login",
		"linux-sshd-no-password-auth",
		"linux-sshd-max-auth-tries",
		"linux-sshd-login-grace-time",
		"linux-sshd-protocol-2",
		"linux-firewall-active",
		"linux-firewall-default-deny",
		"linux-aslr-enabled",
		"linux-no-source-routing",
		"linux-auditd-running",
		"linux-journald-persistent",
		"linux-passwd-perms",
		"linux-shadow-perms",
		"linux-no-empty-passwords",
		"linux-uid-zero-only-root",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatAnsible {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no Ansible strategy", id)
		}
	}
}

func TestRenderSSHDHardening(t *testing.T) {
	f := core.Finding{CheckID: "linux-sshd-no-root-login"}
	s, err := remediate.Default.Render(f, remediate.FormatAnsible)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"ansible.builtin.lineinfile",
		"PermitRootLogin no",
		"PasswordAuthentication no",
		"validate: '/usr/sbin/sshd -t -f %s'",
		"become: true",
	} {
		if !strings.Contains(s.Content, want) {
			t.Errorf("missing %q in tasks:\n%s", want, s.Content)
		}
	}
}

func TestRenderUIDZeroManual(t *testing.T) {
	f := core.Finding{CheckID: "linux-uid-zero-only-root"}
	s, err := remediate.Default.Render(f, remediate.FormatAnsible)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if s.Risk != remediate.RiskManual {
		t.Errorf("Risk = %v, want manual", s.Risk)
	}
}
