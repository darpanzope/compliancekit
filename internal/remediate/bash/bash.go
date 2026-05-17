// Package bash implements remediate.Strategy renderers for the
// FormatBash output. Two purposes:
//
//  1. POSIX-sh one-liners for the Linux/CIS findings — operators
//     who don't run Ansible apply these directly via SSH.
//  2. Wildcard fallback strategy: every finding without a specific
//     bash renderer gets a "# Manual remediation — see Notes."
//     stub with the finding's Message + Resource details. This is
//     the *floor* of coverage: any finding produces at least a
//     bash snippet even if no other format handles it. The POA&M
//     emitter (Phase 10) reads these wildcard outputs to populate
//     manual-action entries.
package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatBash} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatBash {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("bash-sshd-permitrootlogin",
		[]string{"linux-sshd-no-root-login"}, renderSSHDRootLogin)
	register("bash-sshd-passwordauth",
		[]string{"linux-sshd-no-password-auth"}, renderSSHDPasswordAuth)
	register("bash-sshd-maxauthtries",
		[]string{"linux-sshd-max-auth-tries"}, renderSSHDMaxAuthTries)
	register("bash-sshd-logingracetime",
		[]string{"linux-sshd-login-grace-time"}, renderSSHDLoginGraceTime)
	register("bash-sshd-protocol",
		[]string{"linux-sshd-protocol-2"}, renderSSHDProtocol)
	register("bash-firewall-active",
		[]string{"linux-firewall-active"}, renderFirewallActive)
	register("bash-firewall-default-deny",
		[]string{"linux-firewall-default-deny"}, renderFirewallDefaultDeny)
	register("bash-sysctl-aslr",
		[]string{"linux-aslr-enabled"}, renderSysctlASLR)
	register("bash-sysctl-source-routing",
		[]string{"linux-no-source-routing"}, renderSysctlNoSourceRoute)
	register("bash-passwd-perms",
		[]string{"linux-passwd-perms"}, renderPasswdPerms)
	register("bash-shadow-perms",
		[]string{"linux-shadow-perms"}, renderShadowPerms)
	register("bash-auditd",
		[]string{"linux-auditd-running"}, renderAuditdRun)
	register("bash-journald-persistent",
		[]string{"linux-journald-persistent"}, renderJournaldPersistent)
	register("bash-uid-zero-manual",
		[]string{"linux-uid-zero-only-root"}, renderUIDZeroManual)
	register("bash-no-empty-passwords",
		[]string{"linux-no-empty-passwords"}, renderNoEmptyPasswords)

	// Wildcard fallback — last-resort manual sentinel for findings
	// without a strategy. Lives in bash because every operator has
	// a shell; emit a stub the POA&M emitter can pick up.
	register("bash-fallback-manual",
		[]string{"*"}, renderFallbackManual)
}

func renderSSHDRootLogin(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content:     `sudo sed -ri 's/^#?\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd`,
		VerifyCmd:   "sshd -T 2>/dev/null | grep -i permitrootlogin",
		RollbackCmd: `sudo sed -ri 's/^PermitRootLogin no/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && sudo systemctl reload sshd`,
		Notes:       "Verify you have non-root SSH access BEFORE applying — locking yourself out of root over a network with no other user is a recovery scenario.",
	}, nil
}

func renderSSHDPasswordAuth(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content:   `sudo sed -ri 's/^#?\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd`,
		VerifyCmd: "sshd -T 2>/dev/null | grep -i passwordauthentication",
		Notes:     "Confirm key-based access works first. Once disabled, password fallback is gone — emergency console / out-of-band access becomes the recovery path.",
	}, nil
}

func renderSSHDMaxAuthTries(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Idempotent: replace existing MaxAuthTries line OR append.
if sudo grep -qiE '^[[:space:]]*MaxAuthTries[[:space:]]' /etc/ssh/sshd_config; then
  sudo sed -ri 's|^[[:space:]]*MaxAuthTries[[:space:]].*|MaxAuthTries 4|i' /etc/ssh/sshd_config
else
  printf 'MaxAuthTries 4\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
sudo sshd -t && sudo systemctl reload sshd`,
		VerifyCmd: "sshd -T 2>/dev/null | grep -i maxauthtries",
		Notes:     "sshd -t validates the edit BEFORE reload — broken sshd_config doesn't lock you out. CIS recommends MaxAuthTries 4.",
	}, nil
}

func renderSSHDLoginGraceTime(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Idempotent: replace existing LoginGraceTime line OR append.
if sudo grep -qiE '^[[:space:]]*LoginGraceTime[[:space:]]' /etc/ssh/sshd_config; then
  sudo sed -ri 's|^[[:space:]]*LoginGraceTime[[:space:]].*|LoginGraceTime 60|i' /etc/ssh/sshd_config
else
  printf 'LoginGraceTime 60\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
sudo sshd -t && sudo systemctl reload sshd`,
		VerifyCmd: "sshd -T 2>/dev/null | grep -i logingracetime",
		Notes:     "CIS recommends LoginGraceTime ≤ 60 seconds — limits the window a half-open auth attempt can hold a slot.",
	}, nil
}

func renderSSHDProtocol(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Idempotent: replace existing Protocol line OR append.
# Modern OpenSSH (≥ 7.4) dropped Protocol 1 entirely so this is belt-and-braces,
# but auditors still grep for the explicit directive.
if sudo grep -qiE '^[[:space:]]*Protocol[[:space:]]' /etc/ssh/sshd_config; then
  sudo sed -ri 's|^[[:space:]]*Protocol[[:space:]].*|Protocol 2|i' /etc/ssh/sshd_config
else
  printf 'Protocol 2\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
sudo sshd -t && sudo systemctl reload sshd`,
		VerifyCmd: "sshd -T 2>/dev/null | grep -i protocol",
		Notes:     "Modern OpenSSH ignores this directive (Protocol 1 was removed in 7.4) — kept for auditor evidence.",
	}, nil
}

func renderFirewallDefaultDeny(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Distro-aware default-deny for the INPUT chain.
# WARNING: build the inbound allow-list FIRST (at minimum SSH).
. /etc/os-release
case "${ID:-unknown}" in
  ubuntu|debian)
    sudo ufw allow 22/tcp
    sudo ufw default deny incoming
    sudo ufw --force enable
    ;;
  rhel|centos|rocky|almalinux|fedora|amzn)
    sudo systemctl enable --now firewalld
    sudo firewall-cmd --permanent --add-service=ssh
    sudo firewall-cmd --permanent --set-target=DROP --zone=public
    sudo firewall-cmd --reload
    ;;
  alpine)
    sudo apk add --no-cache nftables
    sudo tee /etc/nftables.nft >/dev/null <<'EOF'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 22 accept
  }
}
EOF
    sudo rc-update add nftables boot
    sudo service nftables restart
    ;;
esac`,
		VerifyCmd: "sudo ufw status verbose 2>/dev/null | grep -i default; sudo firewall-cmd --get-default-zone 2>/dev/null; sudo nft list ruleset 2>/dev/null | head",
		Notes:     "Test in a screen/tmux session first — a misconfigured allow-list locks you out. SSH (port 22) is allowed before the deny flips.",
	}, nil
}

func renderFirewallActive(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Debian/Ubuntu:
sudo ufw allow 22/tcp && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw --force enable

# RHEL/CentOS/Rocky:
# sudo dnf install -y firewalld && sudo systemctl enable --now firewalld && sudo firewall-cmd --set-default-zone=public`,
		VerifyCmd: "command -v ufw && sudo ufw status verbose || sudo firewall-cmd --state",
		Notes:     "Allows SSH (port 22) before enabling. Add more `ufw allow <port>` lines for any other inbound services you need.",
	}, nil
}

func renderSysctlASLR(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content:   `echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-aslr.conf && sudo sysctl -p /etc/sysctl.d/99-aslr.conf`,
		VerifyCmd: "sysctl kernel.randomize_va_space",
	}, nil
}

func renderSysctlNoSourceRoute(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: `sudo tee /etc/sysctl.d/99-source-route.conf <<'EOF'
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
sudo sysctl -p /etc/sysctl.d/99-source-route.conf`,
		VerifyCmd: "sysctl net.ipv4.conf.all.accept_source_route",
	}, nil
}

func renderPasswdPerms(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content:   `sudo chmod 0644 /etc/passwd /etc/group && sudo chown root:root /etc/passwd /etc/group`,
		VerifyCmd: "stat -c '%a %U:%G' /etc/passwd /etc/group",
	}, nil
}

func renderShadowPerms(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content:   `sudo chmod 0640 /etc/shadow /etc/gshadow && sudo chown root:shadow /etc/shadow /etc/gshadow`,
		VerifyCmd: "stat -c '%a %U:%G' /etc/shadow /etc/gshadow",
	}, nil
}

func renderAuditdRun(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: `# Debian:
sudo apt-get install -y auditd && sudo systemctl enable --now auditd

# RHEL:
# sudo dnf install -y audit && sudo systemctl enable --now auditd`,
		VerifyCmd: "systemctl is-active auditd",
	}, nil
}

func renderJournaldPersistent(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: `sudo sed -ri 's/^#?\s*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sudo mkdir -p /var/log/journal
sudo chown root:systemd-journal /var/log/journal
sudo chmod 2755 /var/log/journal
sudo systemctl restart systemd-journald`,
		VerifyCmd: "journalctl --header | head -20",
	}, nil
}

func renderUIDZeroManual(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: `# Critical — multiple UID 0 accounts. Investigate ALL.
awk -F: '($3 == 0) {print $1}' /etc/passwd
# Each name besides "root" is either a backdoor or a misconfiguration. Remove with:
# sudo userdel SUSPECT_USER
# Confirm with the system owner before any deletion.`,
		Notes: "Often indicates compromise. Do not auto-remediate.",
	}, nil
}

func renderNoEmptyPasswords(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# List empty-password users, then lock each.
awk -F: '($2 == "") {print $1}' /etc/shadow
# For each user printed:
# sudo passwd -l USERNAME`,
		Notes: "Lock instead of delete — preserves audit trail. Verify the locked users don't have SSH keys still active.",
	}, nil
}

// renderFallbackManual is the wildcard sentinel — runs when no other
// strategy claims the CheckID. Produces a manual-review snippet
// containing the finding's CheckID, Resource ID, and Message so the
// operator has the breadcrumb without the runbook generator needing
// special-case handling for "unmatched."
func renderFallbackManual(f core.Finding) (remediate.Snippet, error) {
	body := fmt.Sprintf(
		"# Manual remediation required for finding %s on resource %s.\n"+
			"# Severity: %s\n"+
			"# Message: %s\n"+
			"# No structured remediation strategy is registered for this CheckID.\n"+
			"# Track via the POA&M emitted alongside this snippet.\n",
		render.ShellQuote(f.CheckID),
		render.ShellQuote(f.Resource.ID),
		f.Severity,
		f.Message,
	)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Add a strategy (any output format) targeting this CheckID to lift it out of the fallback bucket.",
	}, nil
}
