package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.21 phase 1 — kubectl strategies for the 12 pod-security deepening
// checks. Each ships the same two-block shape as the v0.15 starter
// strategies (kubectl patch one-liner + GitOps manifest).

type psExtraEntry struct {
	patch    string
	manifest string
	risk     remediate.RiskClass
	notes    string
}

var psExtraEntries = map[string]psExtraEntry{
	"k8s-pod-share-process-namespace": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"remove","path":"/spec/template/spec/shareProcessNamespace"}]'`,
		manifest: "spec:\n  template:\n    spec:\n      shareProcessNamespace: false   # default; remove if you don't need the field",
		risk:     remediate.RiskReview,
		notes:    "Removing shareProcessNamespace=true breaks debug workflows that rely on cross-container /proc visibility. Migrate to `kubectl debug --target=<container>` first.",
	},
	"k8s-pod-dns-policy-not-default": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/dnsPolicy","value":"ClusterFirst"}]'`,
		manifest: "spec:\n  template:\n    spec:\n      dnsPolicy: ClusterFirst   # routes through CoreDNS; Default reads from node",
		risk:     remediate.RiskSafe,
		notes:    "ClusterFirst is the k8s default for non-hostNetwork pods. The check fails only if dnsPolicy was explicitly set to Default.",
	},
	"k8s-pod-priority-class-explicit": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/priorityClassName","value":"production"}]'`,
		manifest: "---\n# Define the PriorityClass once per cluster:\napiVersion: scheduling.k8s.io/v1\nkind: PriorityClass\nmetadata:\n  name: production\nvalue: 1000\nglobalDefault: false\ndescription: \"production-tier workloads — preempt batch but not system-critical\"\n---\n# Then reference it from every prod workload:\nspec:\n  template:\n    spec:\n      priorityClassName: production",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-host-users-disabled": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/hostUsers","value":false}]'`,
		manifest: "spec:\n  template:\n    spec:\n      hostUsers: false   # k8s 1.30+ user-namespace isolation",
		risk:     remediate.RiskReview,
		notes:    "Test workload compatibility on a canary first — apps that mount host volumes with hard-coded UIDs can break under user-namespace remapping. Requires UserNamespacesSupport feature gate enabled on the cluster (alpha pre-1.28, beta 1.30+).",
	},
	"k8s-pod-fs-group-set": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/securityContext/fsGroup","value":1000}]'`,
		manifest: "spec:\n  template:\n    spec:\n      securityContext:\n        fsGroup: 1000   # match the GID the container expects to write as",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-run-as-group-set": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/securityContext/runAsGroup","value":1000}]'`,
		manifest: "spec:\n  template:\n    spec:\n      securityContext:\n        runAsGroup: 1000   # non-zero GID for every process in every container",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-apparmor-profile-set": {
		patch:    `kubectl annotate pod <NAME> -n <NS> container.apparmor.security.beta.kubernetes.io/<CONTAINER>=runtime/default`,
		manifest: "metadata:\n  annotations:\n    # legacy (pre-1.30) — per-container annotation:\n    container.apparmor.security.beta.kubernetes.io/app: runtime/default\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          # k8s 1.30+ — securityContext field replaces the annotation:\n          securityContext:\n            appArmorProfile:\n              type: RuntimeDefault",
		risk:     remediate.RiskReview,
		notes:    "AppArmor requires a kernel module loaded on the node + a profile by that name; the annotation/field is a no-op on nodes without AppArmor (typical of older AWS AMIs).",
	},
	"k8s-pod-seccomp-not-unconfined": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/securityContext/seccompProfile/type","value":"RuntimeDefault"}]'`,
		manifest: "spec:\n  template:\n    spec:\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault   # never Unconfined outside debug workflows",
		risk:     remediate.RiskReview,
		notes:    "RuntimeDefault enables the container runtime's default syscall allow-list. If a workload uses syscalls the default blocks, switch to `Localhost` with a custom profile rather than reverting to Unconfined.",
	},
	"k8s-pod-runtime-class-explicit": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/runtimeClassName","value":"gvisor"}]'`,
		manifest: "---\n# Define the RuntimeClass once per cluster:\napiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: gvisor\nhandler: runsc   # gVisor's CRI handler; verify your CRI supports it\n---\n# Reference from per-pod spec:\nspec:\n  template:\n    spec:\n      runtimeClassName: gvisor",
		risk:     remediate.RiskManual,
		notes:    "RuntimeClass selection is workload-tier-specific. Apply gVisor / Kata only to untrusted workloads — sandboxed runtimes carry measurable startup + syscall overhead.",
	},
	"k8s-pod-volume-subpath-restricted": {
		patch:    "# No automated patch — subPath usage is workload-specific.\n# Audit each volumeMount + decide between:\n#   1. Separate Volume mounts at distinct mountPaths (preferred)\n#   2. configMap/secret/downwardAPI as the underlying Volume\nkubectl get pod <NAME> -n <NS> -o jsonpath='{.spec.containers[*].volumeMounts[?(@.subPath)]}'",
		manifest: "# Before (subPath against emptyDir — CVE-class):\n#   volumes:\n#     - name: data\n#       emptyDir: {}\n#   containers:\n#     - volumeMounts:\n#         - name: data\n#           mountPath: /var/app/config\n#           subPath: config\n#\n# After (separate volume at the leaf path):\n#   volumes:\n#     - name: app-config\n#       configMap:\n#         name: app-config\n#   containers:\n#     - volumeMounts:\n#         - name: app-config\n#           mountPath: /var/app/config",
		risk:     remediate.RiskManual,
		notes:    "Replacing subPath requires a workload-specific design choice. Prioritize subPath mounts against emptyDir + hostPath; subPath against configMap/secret/downwardAPI is materially safer (the substrate is in-memory, not host filesystem).",
	},
	"k8s-pod-default-service-account": {
		patch:    `kubectl create serviceaccount <APP>-sa -n <NS> && kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/serviceAccountName","value":"<APP>-sa"}]'`,
		manifest: "---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app-sa\n  namespace: <NS>\nautomountServiceAccountToken: false   # opt-in per-pod where actually needed\n---\nspec:\n  template:\n    spec:\n      serviceAccountName: app-sa",
		risk:     remediate.RiskSafe,
		notes:    "Pair with `automountServiceAccountToken: false` on the default SA so accidental future usage surfaces as a token-mount-denied failure rather than ambient privilege.",
	},
	"k8s-pod-supplemental-groups-configured": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/securityContext/supplementalGroups","value":[5000,5001]}]'`,
		manifest: "spec:\n  template:\n    spec:\n      securityContext:\n        supplementalGroups: [5000, 5001]   # GIDs matching shared volume ownership",
		risk:     remediate.RiskReview,
		notes:    "Supplemental groups are only meaningful when the volume actually authorizes by GID (NFS, CIFS, some CSI drivers). If your storage is per-pod RWO, supplementalGroups is decorative.",
	},
}

func init() {
	for id, e := range psExtraEntries {
		id := id
		e := e
		register("kubectl-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := "# === kubectl patch ===\n" + e.patch + "\n\n# === Manifest (GitOps) ===\n" + e.manifest + "\n"
			return remediate.Snippet{
				Risk: e.risk, Idempotent: true, Content: body,
				Notes: e.notes,
			}, nil
		})
	}
}

// v0.21 phase 10 — kubectl backfill for the 2 legacy pod-level check
// IDs that pod_security.go (the v0.11 base) didn't carry kubectl
// strategies for. See backfill_helper.go for the renderer.
func init() {
	registerBackfillIDs(
		"k8s-pod-host-port",
		"k8s-pod-secret-via-env",
	)
}
