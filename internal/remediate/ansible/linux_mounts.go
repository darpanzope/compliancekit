package ansible

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 3 — Ansible strategies for the 15 filesystem-hardening
// checks. Separate-partition fixes require downtime + repartitioning;
// the strategy renders a documented procedure (Ansible can't repartition
// a running root LV safely). Mount-option fixes use ansible.posix.mount
// for idempotent fstab + runtime apply.

var mountSepAnsibleIDs = []string{
	"linux-mount-tmp-separate",
	"linux-mount-var-separate",
	"linux-mount-var-tmp-separate",
	"linux-mount-var-log-separate",
	"linux-mount-var-log-audit-separate",
	"linux-mount-home-separate",
}

func init() {
	for _, id := range mountSepAnsibleIDs {
		id := id
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := `# Repartitioning a running host is a planned change; this stub
# documents the procedure. Build images / new instances with the
# right partition layout from the start.
- name: assert separate filesystem (informational; play won't repartition)
  ansible.builtin.command:
    cmd: findmnt {{ target | mandatory }}
  changed_when: false
  failed_when: lookup('pipe', 'findmnt ' ~ target).startswith('')
  vars:
    target: "/tmp"   # override per inclusion
`
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false, Content: body,
				Notes: "Ansible can't safely repartition a running OS volume. Cycle the host with a new image-builder layout.",
			}, nil
		})
	}
}

var mountOptAnsibleSpecs = map[string]struct {
	target, opt, fstype string
}{
	"linux-mount-tmp-nodev":      {"/tmp", "nodev", "tmpfs"},
	"linux-mount-tmp-nosuid":     {"/tmp", "nosuid", "tmpfs"},
	"linux-mount-tmp-noexec":     {"/tmp", "noexec", "tmpfs"},
	"linux-mount-home-nodev":     {"/home", "nodev", "ext4"},
	"linux-mount-home-nosuid":    {"/home", "nosuid", "ext4"},
	"linux-mount-dev-shm-nodev":  {"/dev/shm", "nodev", "tmpfs"},
	"linux-mount-dev-shm-nosuid": {"/dev/shm", "nosuid", "tmpfs"},
	"linux-mount-dev-shm-noexec": {"/dev/shm", "noexec", "tmpfs"},
	"linux-mount-var-tmp-noexec": {"/var/tmp", "noexec", "ext4"},
}

func init() {
	for id, s := range mountOptAnsibleSpecs {
		id := id
		s := s
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`# ansible.posix.mount applies live + persists via /etc/fstab in one
# idempotent step. Pin opts to the union of defaults + the new flag
# so existing options aren't dropped.
- name: ensure %s has %s
  ansible.posix.mount:
    path: %s
    src: "{{ ansible_mounts | selectattr('mount', 'eq', '%s') | map(attribute='device') | first }}"
    fstype: "{{ ansible_mounts | selectattr('mount', 'eq', '%s') | map(attribute='fstype') | first | default('%s') }}"
    opts: "{{ ansible_mounts | selectattr('mount', 'eq', '%s') | map(attribute='options') | first }},%s"
    state: present
  become: true
`, s.target, s.opt, s.target, s.target, s.target, s.fstype, s.target, s.opt)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				Notes: "Requires ansible.posix collection (ansible-galaxy collection install ansible.posix).",
			}, nil
		})
	}
}
