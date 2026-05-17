package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.20 phase 6 — bash strategies for the 10 sshd-deepening checks.

type sshdBashEntry struct {
	directive, value string
}

var sshdBash = map[string]sshdBashEntry{
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
	for id, e := range sshdBash {
		id := id
		e := e
		register("bash-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`# Idempotent: replace existing %s line OR append.
if sudo grep -qiE '^[[:space:]]*%s[[:space:]]' /etc/ssh/sshd_config; then
  sudo sed -ri 's|^[[:space:]]*%s[[:space:]].*|%s %s|i' /etc/ssh/sshd_config
else
  printf '%s %s\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
sudo sshd -t && sudo systemctl reload sshd`,
				e.directive, e.directive, e.directive, e.directive, e.value, e.directive, e.value)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				VerifyCmd: fmt.Sprintf("sudo sshd -T 2>/dev/null | grep -i %s", e.directive),
				Notes:     "sshd -t validates the edit BEFORE reload — broken sshd_config doesn't lock you out.",
			}, nil
		})
	}
}
