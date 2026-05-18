package k8s

import (
	"context"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 3 — RBAC depth. 10 new privilege-escalation-shaped
// checks, all expressible as verbResourceCheck() invocations against
// specific (apiGroup, resource, verbs) tuples that CIS Kubernetes
// Benchmark §5.1.x calls out as risk patterns.

// rbacExtraEntry encodes one verbResourceCheck-shaped RBAC rule check.
// Mirrors the v0.20 sysctlSpec / sshdSpec shape so adding a new
// pattern is one struct literal.
type rbacExtraEntry struct {
	check        compliancekit.Check
	verbs        []string
	apiGroup     string
	resource     string
	requireMatch bool
}

var rbacExtraEntries = []rbacExtraEntry{
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-update-clusterroles",
			Title:        "Roles should not grant update on ClusterRoles (privilege escalation)",
			Severity:     compliancekit.SeverityCritical,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "`update clusterroles` lets the subject rewrite any " +
				"ClusterRole — including system:masters or cluster-admin — to " +
				"include themselves as subjects via permission flip. Functionally " +
				"equivalent to a backdoor cluster-admin.",
			Remediation: "Strip `update` (+ `patch`) verbs on " +
				"clusterroles.rbac.authorization.k8s.io. The escalate verb " +
				"check (k8s-rbac-escalate) already catches the canonical " +
				"escalation path; this complements it for the direct overwrite case.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "CC6.6"}, "iso27001": {"A.5.15", "A.5.18"},
				"cis-v8": {"6.8"},
			},
			Tags:    []string{"k8s", "rbac", "escalation"},
			Scanner: "rbac.NoUpdateClusterRoles",
		},
		verbs: []string{"update", "patch"}, apiGroup: "rbac.authorization.k8s.io",
		resource: "clusterroles", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-patch-nodes",
			Title:        "Roles should not grant patch on Node objects",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "`patch nodes` allows arbitrary taint manipulation + " +
				"label changes that drive workload scheduling. A subject with " +
				"this verb can cordon every node except one + use it as an " +
				"exfiltration funnel; or strip taints that protect critical " +
				"workloads from preemption.",
			Remediation: "Restrict patch on nodes to operators (cluster-autoscaler) " +
				"with `resourceNames` if granular control is needed.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1"}, "iso27001": {"A.8.2"}, "cis-v8": {"6.8"},
			},
			Tags:    []string{"k8s", "rbac", "nodes"},
			Scanner: "rbac.NoPatchNodes",
		},
		verbs: []string{"patch", "update"}, apiGroup: "", resource: "nodes", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-update-pods-status",
			Title:        "Roles should not grant update on pods/status (liveness spoofing)",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "Writes to pods/status let a subject mark unhealthy " +
				"pods Ready (sending traffic to broken instances) or mark " +
				"healthy pods Failed (forcing reschedule). Used in attacks " +
				"on canary / blue-green deploys to bypass health-gate.",
			Remediation: "pods/status writes are needed only by kubelet + " +
				"specific controllers (node-problem-detector). Restrict to " +
				"those service accounts; deny for anything else.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1"}, "iso27001": {"A.8.2"}, "cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "pods"},
			Scanner: "rbac.NoUpdatePodsStatus",
		},
		verbs: []string{"update", "patch"}, apiGroup: "", resource: "pods/status", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-csr-create",
			Title:        "Roles should not grant create on CertificateSigningRequests",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "Subjects that create CSRs can request certificates " +
				"for any identity, including the kubelet identity. Paired with " +
				"a subject that can approve them (k8s-rbac-csr-approve) it's " +
				"full identity forgery.",
			Remediation: "CSR creation is needed only by kubelets + bootstrap " +
				"workflows. Restrict to specific service accounts; consider " +
				"separating CSR-create from CSR-approve across distinct subjects.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "CC6.7"}, "iso27001": {"A.5.15", "A.8.24"},
				"cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "csr"},
			Scanner: "rbac.NoCSRCreate",
		},
		verbs: []string{"create"}, apiGroup: "certificates.k8s.io",
		resource: "certificatesigningrequests", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-mutatingwebhook-write",
			Title:        "Roles should not grant write on MutatingWebhookConfigurations",
			Severity:     compliancekit.SeverityCritical,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "MutatingWebhookConfiguration writes let the subject " +
				"register a webhook that rewrites every CREATE/UPDATE request — " +
				"injecting privileged containers / overriding image fields / " +
				"adding sidecars. Effectively cluster-admin without the role.",
			Remediation: "Restrict to webhook-management operators with " +
				"resourceNames pinning specific webhooks they own.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "CC6.6"}, "iso27001": {"A.5.15", "A.8.2"},
				"cis-v8": {"6.8"},
			},
			Tags:    []string{"k8s", "rbac", "admission"},
			Scanner: "rbac.NoMutatingWebhookWrite",
		},
		verbs:    []string{"create", "update", "patch", "delete"},
		apiGroup: "admissionregistration.k8s.io",
		resource: "mutatingwebhookconfigurations", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-validatingwebhook-write",
			Title:        "Roles should not grant write on ValidatingWebhookConfigurations",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "ValidatingWebhookConfiguration writes let the subject " +
				"register or remove admission validators — bypassing OPA / " +
				"Gatekeeper / Kyverno enforcement by deregistering them.",
			Remediation: "Restrict to webhook-management operators. Pair with " +
				"audit-log monitoring on " +
				"validatingwebhookconfigurations.admissionregistration.k8s.io.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "CC6.6"}, "iso27001": {"A.5.15"},
				"cis-v8": {"6.8"},
			},
			Tags:    []string{"k8s", "rbac", "admission"},
			Scanner: "rbac.NoValidatingWebhookWrite",
		},
		verbs:    []string{"create", "update", "patch", "delete"},
		apiGroup: "admissionregistration.k8s.io",
		resource: "validatingwebhookconfigurations", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-namespaces-write",
			Title:        "Roles should not grant write on namespaces",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "Namespace creation / deletion is administrative; " +
				"delete on a namespace destroys every resource inside it. " +
				"Update lets the subject change ResourceQuota / LimitRange / " +
				"PodSecurityAdmission labels.",
			Remediation: "Restrict namespace writes to platform / multi-tenant " +
				"control-plane operators. Most workloads need read-only " +
				"namespaces access.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1"}, "iso27001": {"A.8.2"}, "cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "namespaces"},
			Scanner: "rbac.NoNamespacesWrite",
		},
		verbs:    []string{"create", "update", "patch", "delete", "deletecollection"},
		apiGroup: "", resource: "namespaces", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-deletecollection-pods",
			Title:        "Roles should not grant deletecollection on pods",
			Severity:     compliancekit.SeverityMedium,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "deletecollection on pods is a single-call denial-of-" +
				"service primitive — `kubectl delete pods --all` across every " +
				"namespace the subject can see. Used in lateral-movement " +
				"playbooks to disrupt operations while exfiltration runs.",
			Remediation: "Use `delete` with specific resourceNames or labelSelector " +
				"on the verb invocation instead of granting deletecollection.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "A1.2"}, "iso27001": {"A.5.30"},
				"cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "pods", "dos"},
			Scanner: "rbac.NoDeleteCollectionPods",
		},
		verbs: []string{"deletecollection"}, apiGroup: "", resource: "pods", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-create-pods-eviction",
			Title:        "Roles should not grant create on pods/eviction (forced reschedule)",
			Severity:     compliancekit.SeverityMedium,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "pods/eviction lets the subject forcibly evict a pod " +
				"ignoring PodDisruptionBudgets — useful to drain a node, " +
				"useful in DoS playbooks. Cluster-autoscaler + descheduler " +
				"need it; almost nothing else does.",
			Remediation: "Restrict to autoscaler service accounts. For ad-hoc " +
				"eviction, operators should use `kubectl drain` with proper " +
				"PDB handling — not bypass it via the eviction subresource.",
			Frameworks: map[string][]string{
				"soc2": {"A1.2"}, "iso27001": {"A.5.30"},
				"cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "pods", "eviction"},
			Scanner: "rbac.NoCreatePodsEviction",
		},
		verbs: []string{"create"}, apiGroup: "", resource: "pods/eviction", requireMatch: true,
	},
	{
		check: compliancekit.Check{
			ID:           "k8s-rbac-no-update-pods-ephemeralcontainers",
			Title:        "Roles should not grant write on pods/ephemeralcontainers (debug attach)",
			Severity:     compliancekit.SeverityHigh,
			Provider:     "kubernetes",
			Service:      "rbac",
			ResourceType: clusterRoleType,
			Description: "pods/ephemeralcontainers lets a subject attach a " +
				"new container to a running pod with arbitrary image + " +
				"securityContext. Same blast radius as `pods/exec` but " +
				"persistent in spec — a debug container with privileged: " +
				"true is full node compromise from anywhere on the pod's " +
				"network namespace.",
			Remediation: "Restrict to incident-response service accounts only. " +
				"Pair with audit-log monitoring (verbs: create/patch/update on " +
				"pods/ephemeralcontainers) for SOC visibility.",
			Frameworks: map[string][]string{
				"soc2": {"CC6.1", "CC6.6"}, "iso27001": {"A.5.15", "A.8.20"},
				"cis-v8": {"6.7", "6.8"},
			},
			Tags:    []string{"k8s", "rbac", "pods", "ephemeral"},
			Scanner: "rbac.NoUpdatePodsEphemeralContainers",
		},
		verbs:    []string{"create", "update", "patch"},
		apiGroup: "", resource: "pods/ephemeralcontainers", requireMatch: true,
	},
}

// clusterRoleType points at the ClusterRole resource type the existing
// rbac.go checks already iterate. Kept as a constant for readability.
const clusterRoleType = "k8s.cluster_role"

func init() {
	for _, e := range rbacExtraEntries {
		e := e
		compliancekit.Register(e.check, func(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
			return verbResourceCheck(g, e.check, e.verbs, e.apiGroup, e.resource, e.requireMatch), nil
		})
	}
}
