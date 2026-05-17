package compliancekit.k8s.pod.readonly_root_fs

# Rego twin of internal/checks/k8s/pods.go § readonly-root-fs.
# Flags any Pod with at least one container that allows writes
# to the root filesystem.

metadata := {
	"id": "rego-k8s-pod-readonly-root-fs",
	"title": "Pods should mount root filesystem read-only (Rego)",
	"description": "Rego reimplementation of k8s-pod-readonly-root-fs. readOnlyRootFilesystem=true blocks the most common container-escape vectors (overwriting /etc/passwd, dropping shells in /tmp). Most apps work with an emptyDir mounted at /tmp.",
	"severity": "medium",
	"provider": "kubernetes",
	"service": "pods",
	"resource_type": "k8s.pod",
	"remediation": "Set securityContext.readOnlyRootFilesystem=true on every container; mount tmpfs/emptyDir for writable paths.",
	"frameworks": {
		"soc2": ["CC6.1"],
		"iso27001": ["A.8.5"],
		"cis-v8": ["4.1"],
	},
	"tags": ["pod-security", "immutability"],
}

findings := [f |
	r := input.resources[_]
	r.type == "k8s.pod"
	compliancekit.attr_bool(r, "read_only_root_fs") == false
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("pod %q: at least one container without readOnlyRootFilesystem", [r.name]),
	}
]
