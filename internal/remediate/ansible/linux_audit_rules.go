package ansible

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 7 — Ansible strategies for the 10 auditd rule-presence
// checks. Idempotent lineinfile against /etc/audit/rules.d/50-cis.rules
// + a handler that reloads the rules.

type auditRuleAnsEntry struct {
	target, key string
}

var auditRuleAnsible = map[string]auditRuleAnsEntry{
	"linux-audit-rule-passwd":     {"/etc/passwd", "identity"},
	"linux-audit-rule-shadow":     {"/etc/shadow", "identity"},
	"linux-audit-rule-group":      {"/etc/group", "identity"},
	"linux-audit-rule-gshadow":    {"/etc/gshadow", "identity"},
	"linux-audit-rule-sudoers":    {"/etc/sudoers", "scope"},
	"linux-audit-rule-selinux":    {"/etc/selinux", "MAC-policy"},
	"linux-audit-rule-localtime":  {"/etc/localtime", "time-change"},
	"linux-audit-rule-lastlog":    {"/var/log/lastlog", "logins"},
	"linux-audit-rule-mac-policy": {"/etc/apparmor", "MAC-policy"},
}

func init() {
	for id, e := range auditRuleAnsible {
		id := id
		e := e
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`- name: %s — add audit watch on %s
  ansible.builtin.lineinfile:
    path: /etc/audit/rules.d/50-cis.rules
    line: '-w %s -p wa -k %s'
    create: true
    mode: '0640'
  become: true
  notify: reload audit rules
`, id, e.target, e.target, e.key)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
				Notes: "Pair with a `reload audit rules` handler: `command: augenrules --load` (RHEL) or `service: name=auditd state=restarted` (Debian).",
			}, nil
		})
	}
	register("ansible-linux-audit-rule-time-change", []string{"linux-audit-rule-time-change"},
		func(_ core.Finding) (remediate.Snippet, error) {
			body := `- name: audit rule — time-change syscalls
  ansible.builtin.blockinfile:
    path: /etc/audit/rules.d/50-cis.rules
    create: true
    mode: '0640'
    marker: "# {mark} compliancekit time-change"
    block: |
      -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
      -a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change
  become: true
  notify: reload audit rules
`
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
			}, nil
		})
}
