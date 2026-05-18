package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 7 — bash strategies for the 10 auditd rule-presence
// checks. Each strategy appends the missing rule to
// /etc/audit/rules.d/50-cis.rules + reloads.

type auditRuleBashEntry struct {
	target string // path to watch
	key    string // -k tag for the rule
}

var auditRuleBash = map[string]auditRuleBashEntry{
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
	for id, e := range auditRuleBash {
		id := id
		e := e
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`# Append the audit watch rule + reload.
sudo grep -qE -- '-w %s' /etc/audit/rules.d/50-cis.rules 2>/dev/null \
  || printf -- '-w %s -p wa -k %s\n' | sudo tee -a /etc/audit/rules.d/50-cis.rules >/dev/null

# Apply the new rules (RHEL family + Debian both work):
sudo augenrules --load 2>/dev/null || sudo systemctl restart auditd`,
				e.target, e.target, e.key)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
				VerifyCmd: fmt.Sprintf("sudo auditctl -l | grep %s", e.target),
			}, nil
		})
	}
	// time-change rule (syscall, not a watch — needs a different shape)
	register("bash-linux-audit-rule-time-change", []string{"linux-audit-rule-time-change"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `# Time-change syscalls (adjtimex / settimeofday / clock_settime / stime).
sudo grep -q 'adjtimex,settimeofday' /etc/audit/rules.d/50-cis.rules 2>/dev/null || \
  printf '%s\n%s\n' \
    '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change' \
    '-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change' \
  | sudo tee -a /etc/audit/rules.d/50-cis.rules >/dev/null
sudo augenrules --load 2>/dev/null || sudo systemctl restart auditd`
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
				VerifyCmd: "sudo auditctl -l | grep adjtimex",
			}, nil
		})
}
