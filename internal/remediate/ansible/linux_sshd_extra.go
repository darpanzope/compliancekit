package ansible

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 6 — Ansible strategies for the 10 sshd-deepening checks.

type sshdAnsEntry struct {
	directive, value string
}

var sshdAnsible = map[string]sshdAnsEntry{
	"linux-sshd-permit-empty-passwords":   {"PermitEmptyPasswords", "no"},
	"linux-sshd-x11-forwarding-disabled":  {"X11Forwarding", "no"},
	"linux-sshd-permit-user-environment":  {"PermitUserEnvironment", "no"},
	"linux-sshd-ignore-rhosts":            {"IgnoreRhosts", "yes"},
	"linux-sshd-hostbased-auth-disabled":  {"HostbasedAuthentication", "no"},
	"linux-sshd-client-alive-interval":    {"ClientAliveInterval", "300"},
	"linux-sshd-client-alive-count-max":   {"ClientAliveCountMax", "3"},
	"linux-sshd-max-sessions":             {"MaxSessions", "10"},
	"linux-sshd-banner-set":               {"Banner", "/etc/issue.net"},
	"linux-sshd-loglevel-info-or-verbose": {"LogLevel", "VERBOSE"},
}

func init() {
	for id, e := range sshdAnsible {
		id := id
		e := e
		register("ansible-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`- name: %s — set %s in sshd_config
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^[[:space:]]*%s[[:space:]]'
    line: '%s %s'
    state: present
    validate: 'sshd -t -f %%s'
  become: true
  notify: reload sshd
`, id, e.directive, e.directive, e.directive, e.value)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				Notes: "validate: forces sshd -t before the file is replaced. Pair with a `reload sshd` handler in your role.",
			}, nil
		})
	}
}
