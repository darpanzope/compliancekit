package ansible

import (
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 9 — Ansible strategies for the 10 packages/MAC checks.

func init() {
	register("ansible-linux-mac-selinux-enforcing",
		[]string{"linux-mac-selinux-enforcing"},
		func(_ core.Finding) (remediate.Snippet, error) {
			body := `- name: SELinux enforcing — live + persistent
  block:
    - ansible.builtin.command: setenforce 1
      changed_when: true
    - ansible.posix.selinux:
        policy: targeted
        state: enforcing
  become: true
`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				Notes: "Requires ansible.posix collection.",
			}, nil
		})

	register("ansible-linux-mac-apparmor-active",
		[]string{"linux-mac-apparmor-active"},
		func(_ core.Finding) (remediate.Snippet, error) {
			body := `- name: AppArmor — install + enable + enforce profiles
  block:
    - ansible.builtin.apt:
        name: [apparmor, apparmor-utils]
        state: present
    - ansible.builtin.systemd:
        name: apparmor
        enabled: true
        state: started
    - ansible.builtin.command: aa-enforce /etc/apparmor.d/*
      changed_when: true
  become: true
`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
			}, nil
		})

	manualHints := map[string]string{
		"linux-pkg-gpg-keys-trusted-only":          "apt-key list 2>/dev/null",
		"linux-pkg-no-unattended-upgrades":         "systemctl is-active unattended-upgrades 2>/dev/null || systemctl is-active dnf-automatic.timer 2>/dev/null",
		"linux-pkg-aide-installed":                 "which aide",
		"linux-pkg-no-orphaned-packages":           "apt-get autoremove --dry-run 2>/dev/null || dnf autoremove --assumeno 2>/dev/null",
		"linux-pkg-prelink-absent":                 "dpkg -l prelink 2>/dev/null || rpm -q prelink 2>/dev/null",
		"linux-mac-selinux-no-permissive-services": "semanage permissive -l 2>/dev/null",
		"linux-mac-apparmor-no-complain-mode":      "aa-status",
		"linux-pkg-cron-restricted-to-root":        "ls -la /etc/cron.allow /etc/cron.deny 2>/dev/null",
	}
	for id, hint := range manualHints {
		id := id
		hint := hint
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := "- name: " + id + " — inspect (manual-verify)\n  ansible.builtin.command:\n    cmd: " + hint + "\n  register: out\n  changed_when: false\n  failed_when: false\n  become: true\n- ansible.builtin.debug:\n    var: out.stdout_lines\n"
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: true, Content: body,
			}, nil
		})
	}
}
