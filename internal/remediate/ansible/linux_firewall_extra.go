package ansible

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 8 — Ansible strategies for the 10 firewall-depth checks.

func init() {
	register("ansible-linux-firewall-ufw-default-deny-outgoing",
		[]string{"linux-firewall-ufw-default-deny-outgoing"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `# WARNING: flips default outgoing to deny — build the allow-list FIRST.
- name: ufw — allow essential egress
  community.general.ufw:
    rule: allow
    direction: out
    to_port: "{{ item.port }}"
    proto: "{{ item.proto }}"
  loop:
    - { port: 443, proto: tcp }
    - { port: 53,  proto: udp }
    - { port: 123, proto: udp }
  become: true

- name: ufw — default deny outgoing
  community.general.ufw:
    direction: outgoing
    default: deny
  become: true
`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				Notes: "Requires community.general collection. Test in a non-prod environment first.",
			}, nil
		})

	register("ansible-linux-firewall-some-active",
		[]string{"linux-firewall-some-active"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `- name: ensure a firewall is active (distro-aware)
  block:
    - ansible.builtin.systemd:
        name: ufw.service
        enabled: true
        state: started
      when: ansible_os_family == 'Debian'
    - ansible.builtin.systemd:
        name: nftables.service
        enabled: true
        state: started
      when: ansible_os_family == 'RedHat'
  become: true
`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
			}, nil
		})

	register("ansible-linux-firewall-nftables-on-rhel",
		[]string{"linux-firewall-nftables-on-rhel"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `- name: nftables on RHEL-family
  ansible.builtin.systemd:
    name: nftables
    enabled: true
    state: started
  when: ansible_os_family == 'RedHat'
  become: true
`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
			}, nil
		})

	manualFirewallHints := map[string]string{
		"linux-firewall-loopback-allowed":         "iptables -L INPUT | grep -i lo",
		"linux-firewall-icmp-input-restricted":    "iptables -L INPUT | grep -i icmp",
		"linux-firewall-ipv6-rules-present":       "ip6tables -L | head",
		"linux-firewall-egress-policy-documented": "echo 'Document the allow-list in your runbook'",
		"linux-firewall-rules-logged":             "iptables -L | grep LOG",
		"linux-firewall-ssh-rate-limited":         "ufw status verbose | grep -i limit",
		"linux-firewall-dns-egress-restricted":    "iptables -L OUTPUT | grep 53",
	}
	for id, hint := range manualFirewallHints {
		id := id
		hint := hint
		register("ansible-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := "- name: " + id + " — inspect (manual-verify)\n  ansible.builtin.command:\n    cmd: " + hint + "\n  register: out\n  changed_when: false\n  failed_when: false\n  become: true\n- ansible.builtin.debug:\n    var: out.stdout_lines\n"
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: true, Content: body,
				Notes: "Surface output via debug task for audit evidence.",
			}, nil
		})
	}
}
