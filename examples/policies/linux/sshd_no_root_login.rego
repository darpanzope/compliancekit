package compliancekit.linux.sshd.no_root_login

# Rego twin of internal/checks/linux/host.go § sshd-no-root-login.
# Flags any linux.host whose sshd_config does not disable root SSH.

metadata := {
	"id": "rego-linux-sshd-no-root-login",
	"title": "sshd must disable direct root login (Rego)",
	"description": "Rego reimplementation of linux-sshd-no-root-login. PermitRootLogin no forces administrators to log in as a named user and sudo, preserving the audit trail. prohibit-password is acceptable when key-based root access is mandatory.",
	"severity": "high",
	"provider": "linux",
	"service": "sshd",
	"resource_type": "linux.host",
	"remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config and `systemctl reload sshd`.",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.2"],
		"cis-v8": ["4.6"],
	},
	"tags": ["host", "sshd", "authentication"],
}

findings := [f |
	r := input.resources[_]
	r.type == "linux.host"
	v := compliancekit.attr_str(r, "sshd_permit_root_login")
	v != "no"
	v != "prohibit-password"
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("host %q: PermitRootLogin=%q (want \"no\" or \"prohibit-password\")", [r.name, v]),
	}
]
