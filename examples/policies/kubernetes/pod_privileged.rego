package compliancekit.k8s.pod.privileged

# Rego twin of internal/checks/k8s/pods.go § privileged.
# Flags any Pod whose securityContext.privileged is true.

metadata := {
	"id": "rego-k8s-pod-privileged",
	"title": "Pods must not run privileged containers (Rego)",
	"description": "Rego reimplementation of k8s-pod-privileged. Privileged=true grants the container all host capabilities — equivalent to root on the node.",
	"severity": "critical",
	"provider": "kubernetes",
	"service": "pods",
	"resource_type": "k8s.pod",
	"remediation": "Remove securityContext.privileged from every container. Use explicit capabilities.add for the specific kernel APIs the workload needs (CAP_NET_ADMIN, etc.).",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.5"],
		"cis-v8": ["4.1"],
	},
	"tags": ["pod-security", "privilege-escalation"],
}

findings := [f |
	r := input.resources[_]
	r.type == "k8s.pod"
	compliancekit.attr_bool(r, "privileged") == true
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("pod %q: at least one privileged container", [r.name]),
	}
]
