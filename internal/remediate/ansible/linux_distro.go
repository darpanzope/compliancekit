package ansible

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 1 — Ansible strategy for linux-distro-supported.
// There's no automated remediation; the snippet emits an assert
// task that the operator can wire into a pre-flight check so a
// runbook playbook bails on unsupported hosts.

func init() {
	register("ansible-linux-distro-supported",
		[]string{"linux-distro-supported"}, renderDistroSupported)
}

func renderDistroSupported(_ compliancekit.Finding) (remediate.Snippet, error) {
	body := `# Pre-flight gate: refuse to run the hardening playbook on a distro
# compliancekit doesn't model. Add to the top of your site.yml.
- name: distro on the compliancekit-supported allowlist
  ansible.builtin.assert:
    that:
      - ansible_facts['distribution'] | lower in ['ubuntu', 'debian', 'rhel', 'centos', 'rocky', 'almalinux', 'fedora', 'alpine', 'amzn']
    fail_msg: "distro {{ ansible_facts['distribution'] }} {{ ansible_facts['distribution_version'] }} is not on the compliancekit allowlist; per-distro hardening checks may misclassify."
    success_msg: "distro {{ ansible_facts['distribution'] }} {{ ansible_facts['distribution_version'] }} supported"
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		Notes: "Assert task only. Either migrate to a supported distro or open an issue to extend the allowlist (internal/checks/linux/distro.go).",
	}, nil
}
