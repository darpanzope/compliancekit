package compliancekit.linux.aslr_enabled

# Rego twin of internal/checks/linux/host.go § aslr-enabled.
# Flags any linux.host where kernel.randomize_va_space is not 2.

metadata := {
	"id": "rego-linux-aslr-enabled",
	"title": "Linux hosts must enable full ASLR (Rego)",
	"description": "Rego reimplementation of linux-aslr-enabled. kernel.randomize_va_space=2 enables full ASLR for stack + heap + libraries + brk; weakens stack-smashing and ROP exploits.",
	"severity": "medium",
	"provider": "linux",
	"service": "kernel",
	"resource_type": "linux.host",
	"remediation": "echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-aslr.conf && sudo sysctl -p /etc/sysctl.d/99-aslr.conf",
	"frameworks": {
		"soc2": ["CC6.6"],
		"iso27001": ["A.8.9"],
		"cis-v8": ["4.1"],
	},
	"tags": ["host", "kernel-hardening"],
}

findings := [f |
	r := input.resources[_]
	r.type == "linux.host"
	compliancekit.attr_str(r, "kernel_randomize_va_space") != "2"
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("host %q: kernel.randomize_va_space=%q (want \"2\")", [r.name, compliancekit.attr_str(r, "kernel_randomize_va_space")]),
	}
]
