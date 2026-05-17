package compliancekit.linux.firewall_active

# Rego twin of internal/checks/linux/host.go § firewall-active.
# Flags any linux.host with no active firewall (ufw / firewalld / nftables).

metadata := {
	"id": "rego-linux-firewall-active",
	"title": "Linux hosts must run an active firewall (Rego)",
	"description": "Rego reimplementation of linux-firewall-active. Any of ufw / firewalld / nftables counts as active; the check fails only when none of them is running. A host with no firewall trusts everything reaching it on the network.",
	"severity": "high",
	"provider": "linux",
	"service": "firewall",
	"resource_type": "linux.host",
	"remediation": "Debian: sudo ufw allow 22/tcp && sudo ufw default deny incoming && sudo ufw --force enable. RHEL: sudo dnf install -y firewalld && sudo systemctl enable --now firewalld.",
	"frameworks": {
		"soc2": ["CC6.6"],
		"iso27001": ["A.8.22"],
		"cis-v8": ["12.2"],
	},
	"tags": ["host", "network-security", "firewall"],
}

findings := [f |
	r := input.resources[_]
	r.type == "linux.host"
	compliancekit.attr_bool(r, "firewall_active") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("host %q: no active firewall detected", [r.name]),
	}
]
