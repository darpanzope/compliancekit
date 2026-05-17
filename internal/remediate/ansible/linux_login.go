package ansible

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 5 — Ansible strategies for the 10 PAM/sudo/login.defs
// checks. login.defs entries use ansible.builtin.lineinfile;
// manual-verify checks render a debug task + a stub the operator
// can extend per distro.

type loginDefsAnsEntry struct {
	key, val string
}

var loginDefsAnsible = map[string]loginDefsAnsEntry{
	"linux-login-defs-pass-max-days":  {"PASS_MAX_DAYS", "365"},
	"linux-login-defs-pass-min-days":  {"PASS_MIN_DAYS", "1"},
	"linux-login-defs-pass-warn-age":  {"PASS_WARN_AGE", "7"},
	"linux-login-defs-encrypt-method": {"ENCRYPT_METHOD", "YESCRYPT"},
	"linux-login-defs-umask":          {"UMASK", "027"},
}

var manualLoginAnsHints = map[string]string{
	"linux-sudo-nopasswd-audit":      "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/",
	"linux-sudo-secure-path":         "grep ^Defaults.*secure_path /etc/sudoers",
	"linux-sudo-logging":             `grep -E '^Defaults.*(logfile|syslog)' /etc/sudoers`,
	"linux-pam-faillock-configured":  `grep -E 'pam_faillock|pam_tally2' /etc/pam.d/*`,
	"linux-pam-pwquality-configured": "cat /etc/security/pwquality.conf | grep -v '^#'",
}

func init() {
	for id, e := range loginDefsAnsible {
		id := id
		e := e
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`- name: %s — set %s in /etc/login.defs
  ansible.builtin.lineinfile:
    path: /etc/login.defs
    regexp: '^[[:space:]]*%s[[:space:]]'
    line: '%s   %s'
    state: present
  become: true
`, id, e.key, e.key, e.key, e.val)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
			}, nil
		})
	}
	for id, hint := range manualLoginAnsHints {
		id := id
		hint := hint
		register("ansible-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`- name: %s — inspect current state (manual-verify)
  ansible.builtin.command:
    cmd: %s
  register: %s_out
  changed_when: false
  failed_when: false
  become: true

- name: %s — surface output for evidence
  ansible.builtin.debug:
    var: %s_out.stdout_lines
`, id, hint, escapeForVar(id), id, escapeForVar(id))
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: true, Content: body,
				Notes: "Captures inspection output via debug task — operator records the evidence + waives via waivers.yaml.",
			}, nil
		})
	}
}

// escapeForVar makes a check id usable as an Ansible variable name
// (strip dashes).
func escapeForVar(id string) string {
	out := []byte{}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c == '-' {
			out = append(out, '_')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
