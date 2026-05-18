package bash

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 8 — bash strategies for the 10 firewall-depth checks.

func init() {
	register("bash-linux-firewall-ufw-default-deny-outgoing",
		[]string{"linux-firewall-ufw-default-deny-outgoing"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true,
				Content: `# WARNING: this drops every outbound connection that isn't explicitly allowed.
# Build the allow-list FIRST, then flip the default.
sudo ufw allow out 443/tcp comment 'HTTPS'
sudo ufw allow out 53      comment 'DNS'
sudo ufw allow out 123     comment 'NTP'
sudo ufw default deny outgoing
sudo ufw reload`,
				VerifyCmd: "sudo ufw status verbose | grep -i outgoing",
				Notes:     "Test in a screen/tmux session first — a misconfigured allow-list can lock the host out of package updates.",
			}, nil
		})

	register("bash-linux-firewall-some-active",
		[]string{"linux-firewall-some-active"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true,
				Content: `# Enable the appropriate firewall per distro.
. /etc/os-release
case "${ID:-unknown}" in
  ubuntu|debian)
    sudo apt-get install -y ufw
    sudo ufw enable
    ;;
  rhel|centos|rocky|almalinux|fedora|amzn)
    sudo systemctl enable --now nftables firewalld 2>/dev/null || sudo systemctl enable --now nftables
    ;;
  alpine)
    sudo apk add --no-cache nftables
    sudo rc-update add nftables boot
    sudo service nftables start
    ;;
esac`,
				VerifyCmd: "sudo ufw status 2>/dev/null; sudo systemctl is-active nftables 2>/dev/null",
			}, nil
		})

	register("bash-linux-firewall-nftables-on-rhel",
		[]string{"linux-firewall-nftables-on-rhel"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true,
				Content: `sudo systemctl enable --now nftables
# Migrate any legacy iptables rules:
sudo iptables-save > /tmp/iptables.bak
sudo iptables-restore-translate -f /tmp/iptables.bak | sudo tee /etc/nftables.conf >/dev/null
sudo systemctl restart nftables`,
				VerifyCmd: "systemctl is-active nftables",
			}, nil
		})

	// Manual-verify hints — same shape as Phase 5 PAM/sudo strategies.
	manualFirewallHints := map[string]string{
		"linux-firewall-loopback-allowed":         "sudo iptables -L INPUT | grep -i lo",
		"linux-firewall-icmp-input-restricted":    "sudo iptables -L INPUT | grep -i icmp",
		"linux-firewall-ipv6-rules-present":       "sudo ip6tables -L | head",
		"linux-firewall-egress-policy-documented": "echo 'Document the allow-list in your runbook' >&2",
		"linux-firewall-rules-logged":             "sudo iptables -L | grep LOG",
		"linux-firewall-ssh-rate-limited":         "sudo ufw status verbose | grep -i limit",
		"linux-firewall-dns-egress-restricted":    "sudo iptables -L OUTPUT | grep 53",
	}
	for id, hint := range manualFirewallHints {
		id := id
		hint := hint
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false,
				Content: "# Manual-verify — inspect the current state, record evidence in waivers.yaml.\n" + hint + "\n",
				Notes:   "Firewall rule semantics vary widely; verify per host then waive via waivers.yaml.",
			}, nil
		})
	}
}
