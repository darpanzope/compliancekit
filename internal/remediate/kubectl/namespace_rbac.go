package kubectl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func init() {
	register("k8s-namespace-psa-label",
		[]string{"k8s-namespace-psa-label"},
		renderNamespacePSALabel)
	register("k8s-namespace-limitrange-missing",
		[]string{"k8s-namespace-limitrange-missing", "k8s-limitrange-container-defaults"},
		renderNamespaceLimitRange)
	register("k8s-namespace-resourcequota-missing",
		[]string{"k8s-namespace-resourcequota-missing"},
		renderNamespaceResourceQuota)

	// RBAC findings whose remediation requires permission auditing.
	register("k8s-rbac-manual",
		[]string{
			"k8s-rbac-full-wildcard",
			"k8s-rbac-wildcard-apigroups",
			"k8s-rbac-wildcard-resources",
			"k8s-rbac-wildcard-verbs",
			"k8s-rbac-cluster-admin-non-system",
			"k8s-rbac-escalate",
			"k8s-rbac-impersonate",
			"k8s-rbac-anonymous-bind",
			"k8s-rbac-secrets-writable",
			"k8s-rbac-pods-exec",
			"k8s-rbac-create-pods",
			"k8s-rbac-csr-approve",
			"k8s-rbac-tokenrequest",
		},
		renderRBACManual)
}

func renderNamespacePSALabel(f compliancekit.Finding) (remediate.Snippet, error) {
	ns := f.Resource.Name
	if ns == "" {
		ns = defaultNamespace
	}
	cmd := fmt.Sprintf(
		"kubectl label namespace %s pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest --overwrite",
		render.ShellQuote(ns),
	)
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
`, ns)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl get namespace %s --show-labels", render.ShellQuote(ns)),
		Notes:      "PodSecurity 'restricted' is the strictest profile — verify all workloads in the namespace pass the policy first (apply pod-security.kubernetes.io/audit=restricted without enforce, watch logs for a week). Use 'baseline' for namespaces that can't move to restricted yet.",
		Refs: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-admission/",
		},
	}, nil
}

func renderNamespaceLimitRange(f compliancekit.Finding) (remediate.Snippet, error) {
	ns := f.Resource.Name
	if ns == "" {
		ns = defaultNamespace
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: %s
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    min:
      cpu: "10m"
      memory: "32Mi"
    max:
      cpu: "4"
      memory: "8Gi"
`, ns)
	cmd := fmt.Sprintf("kubectl apply -n %s -f - <<'EOF'\n%sEOF", render.ShellQuote(ns), manifest)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl get limitrange -n %s", render.ShellQuote(ns)),
		Notes:      "LimitRange fills in defaults for pods that don't specify resources and rejects pods exceeding the max. Tune defaults to typical workload sizes — defaults too low cause OOMKill; too high lets a single misbehaving pod monopolize the namespace.",
		Refs: []string{
			"https://kubernetes.io/docs/concepts/policy/limit-range/",
		},
	}, nil
}

func renderNamespaceResourceQuota(f compliancekit.Finding) (remediate.Snippet, error) {
	ns := f.Resource.Name
	if ns == "" {
		ns = defaultNamespace
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: %s
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    persistentvolumeclaims: "20"
    services.loadbalancers: "2"
    services.nodeports: "0"
    pods: "100"
    secrets: "50"
    configmaps: "50"
`, ns)
	cmd := fmt.Sprintf("kubectl apply -n %s -f - <<'EOF'\n%sEOF", render.ShellQuote(ns), manifest)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl describe resourcequota -n %s", render.ShellQuote(ns)),
		Notes:      "Caps total resource consumption in the namespace. services.nodeports=0 blocks NodePort services (compliance + security positive); set to a non-zero number if your cluster relies on them. Tune limits.* to actual capacity expectations; tight quotas cause scheduling failures.",
		Refs: []string{
			"https://kubernetes.io/docs/concepts/policy/resource-quotas/",
		},
	}, nil
}

func renderRBACManual(f compliancekit.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation — RBAC permission audit required.\n",
		Notes: fmt.Sprintf(
			"RBAC finding %q affects %q. Replacement strategy: 1) enumerate the subject's API calls over the past 30 days (kube-apiserver audit log: --audit-log-path; or via a vendor like Falco / Cilium Tetragon); 2) compute the smallest verb×resource×apiGroup set that covers them; 3) author a replacement Role/ClusterRole; 4) swap the RoleBinding/ClusterRoleBinding's roleRef; 5) monitor permission-denied events for 24h. Track via POA&M.",
			f.CheckID, name),
		Refs: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
		},
	}, nil
}
