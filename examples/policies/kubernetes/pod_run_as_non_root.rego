package compliancekit.k8s.pod.run_as_non_root

# Rego twin of internal/checks/k8s/pods.go § run-as-non-root.
# Flags any Pod whose securityContext.runAsNonRoot is not true.

metadata := {
	"id": "rego-k8s-pod-run-as-non-root",
	"title": "Pods must set securityContext.runAsNonRoot=true (Rego)",
	"description": "Rego reimplementation of k8s-pod-run-as-non-root. Containers running as UID 0 inherit root capabilities; container-escape attacks gain root on the node.",
	"severity": "high",
	"provider": "kubernetes",
	"service": "pods",
	"resource_type": "k8s.pod",
	"remediation": "Set spec.securityContext.runAsNonRoot=true plus runAsUser>=1000 on the pod or container.",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.5"],
		"cis-v8": ["4.1"],
	},
	"tags": ["pod-security", "least-privilege"],
}

findings := [f |
	r := input.resources[_]
	r.type == "k8s.pod"
	compliancekit.attr_bool(r, "run_as_non_root") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("pod %q: runAsNonRoot not set or false", [r.name]),
	}
]
