package bash

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 5 — bash strategies for the 10 PAM/sudo/login.defs
// checks. The five login.defs checks render an idempotent sed
// edit; the five manual-verify checks render a documented inspection
// + evidence-collection one-liner.

type loginDefsBashEntry struct {
	key, val string
}

var loginDefsBash = map[string]loginDefsBashEntry{
	"linux-login-defs-pass-max-days":  {"PASS_MAX_DAYS", "365"},
	"linux-login-defs-pass-min-days":  {"PASS_MIN_DAYS", "1"},
	"linux-login-defs-pass-warn-age":  {"PASS_WARN_AGE", "7"},
	"linux-login-defs-encrypt-method": {"ENCRYPT_METHOD", "YESCRYPT"},
	"linux-login-defs-umask":          {"UMASK", "027"},
}

var manualLoginHints = map[string]string{
	"linux-sudo-nopasswd-audit":      "sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/",
	"linux-sudo-secure-path":         "sudo grep ^Defaults.*secure_path /etc/sudoers",
	"linux-sudo-logging":             `sudo grep -E '^Defaults.*(logfile|syslog)' /etc/sudoers`,
	"linux-pam-faillock-configured":  `sudo grep -E 'pam_faillock|pam_tally2' /etc/pam.d/*`,
	"linux-pam-pwquality-configured": "sudo cat /etc/security/pwquality.conf | grep -v '^#'",
}

func init() {
	for id, e := range loginDefsBash {
		id := id
		e := e
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := renderLoginDefsBash(e)
			return remediate.Snippet{
				Risk: remediate.RiskSafe, Idempotent: true, Content: body,
				VerifyCmd: fmt.Sprintf("grep ^%s /etc/login.defs", e.key),
			}, nil
		})
	}
	for id, hint := range manualLoginHints {
		id := id
		hint := hint
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf("# Manual-verify — inspect the current state, record evidence in waivers.yaml.\n%s\n", hint)
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false, Content: body,
				Notes: "Per-distro PAM + sudoers parsing is deferred to a future milestone. Capture the output as evidence + waive via waivers.yaml.",
			}, nil
		})
	}
}

func renderLoginDefsBash(e loginDefsBashEntry) string {
	// Idempotent sed: replace if line present, otherwise append.
	return strings.TrimLeft(fmt.Sprintf(`if grep -qE '^[[:space:]]*%s[[:space:]]' /etc/login.defs; then
  sudo sed -ri 's|^[[:space:]]*%s[[:space:]].*|%s   %s|' /etc/login.defs
else
  printf '%s   %s\n' | sudo tee -a /etc/login.defs >/dev/null
fi`, e.key, e.key, e.key, e.val, e.key, e.val), "\n")
}
