package k8s

import (
	"context"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 1 — verb-based dangerous-action RBAC checks split out
// of rbac.go (1045 → 3 files) to satisfy the 600-LoC invariant
// enforced by internal/repocheck. Each check is a thin wrapper around
// verbResourceCheck() or ruleVerbCheck() in rbac.go.
//
// 9 checks total — one per (verb, resource, apiGroup) tuple CIS
// Kubernetes Benchmark §5.1.x calls out as a privilege-escalation
// primitive.

// ----- Verb-based dangerous-action checks -------------------------
// Each is a thin wrapper around verbResourceCheck.

var CheckRBACSecretsRead = core.Check{
	ID:           "k8s-rbac-secrets-readable",
	Title:        "Roles should not grant read access to secrets broadly",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`get/list/watch` on secrets exposes every credential " +
		"in the namespace (or cluster, for ClusterRoles). Operators " +
		"frequently grant this for the wrong reason — what they want " +
		"is access to a single ConfigMap or one specific secret. Use " +
		"`resourceNames` to narrow.",
	Remediation: "If the role only needs to read one secret, set " +
		"`resourceNames: [the-secret-name]`. Otherwise consider whether " +
		"the secret could be a projected token, environment variable, " +
		"or external secrets reference.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.10"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "secrets", "least-privilege"},
	Scanner: "rbac.SecretsRead",
}

func RBACSecretsRead(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACSecretsRead, []string{"get", "list", "watch"},
		"", "secrets", false), nil
}

var CheckRBACSecretsWrite = core.Check{
	ID:           "k8s-rbac-secrets-writable",
	Title:        "Roles should not grant write access to secrets",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`create/update/patch/delete` on secrets lets the " +
		"subject overwrite credentials used by other workloads — a " +
		"direct privilege escalation. Almost no application has a " +
		"legitimate need; if one does, it should be a ClusterOperator " +
		"with a much narrower scope.",
	Remediation: "Strip write verbs on secrets. For controllers that " +
		"manage their own secrets, use `resourceNames` to lock the " +
		"grant to a single named secret.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.10"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "secrets"},
	Scanner: "rbac.SecretsWrite",
}

func RBACSecretsWrite(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACSecretsWrite, []string{"create", "update", "patch", "delete"},
		"", "secrets", false), nil
}

var CheckRBACPodsExec = core.Check{
	ID:           "k8s-rbac-pods-exec",
	Title:        "Roles should not grant pods/exec",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`pods/exec` lets the subject open a shell inside any " +
		"matching pod, bypassing every container-level security " +
		"control. With this verb, the audit trail goes from `kubectl " +
		"apply` events to interactive shell traffic the kube-apiserver " +
		"does not record.",
	Remediation: "Reserve pods/exec for break-glass roles bound only to " +
		"a small set of named humans. CI/CD pipelines and applications " +
		"should not have it.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.16"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "exec"},
	Scanner: "rbac.PodsExec",
}

func RBACPodsExec(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACPodsExec, []string{"create", "*"},
		"", "pods/exec", false), nil
}

var CheckRBACPodsPortforward = core.Check{
	ID:           "k8s-rbac-pods-portforward",
	Title:        "Roles should not grant pods/portforward",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`pods/portforward` opens a tunnel from kubectl to any " +
		"port in a target pod, bypassing Services and NetworkPolicies. " +
		"It is a debugging primitive and should not be a normal " +
		"workload permission.",
	Remediation: "Restrict pods/portforward to operator/SRE roles bound " +
		"to named humans, not pipelines or applications.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.16"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "portforward"},
	Scanner: "rbac.PodsPortforward",
}

func RBACPodsPortforward(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACPodsPortforward, []string{"create", "*"},
		"", "pods/portforward", false), nil
}

var CheckRBACImpersonate = core.Check{
	ID:           "k8s-rbac-impersonate",
	Title:        "Roles should not grant the impersonate verb",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`impersonate` lets the subject act as any user, group, " +
		"or ServiceAccount. It exists for trusted gateway proxies like " +
		"kubectl-as flows — any other role with this verb is a " +
		"privilege escalation primitive.",
	Remediation: "Strip the impersonate verb. If a controller genuinely " +
		"needs it (auth proxy, dashboard), document the rationale and " +
		"limit `resourceNames` to specific subjects.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "impersonate", "critical"},
	Scanner: "rbac.Impersonate",
}

func RBACImpersonate(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return ruleVerbCheck(g, CheckRBACImpersonate, "impersonate"), nil
}

var CheckRBACEscalate = core.Check{
	ID:           "k8s-rbac-escalate",
	Title:        "Roles should not grant the escalate verb on roles",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`escalate` on roles/clusterroles lets the subject add " +
		"rules to a role that exceed what the subject itself holds. " +
		"It defeats the privilege-escalation prevention K8s applies " +
		"to RBAC mutations.",
	Remediation: "Remove the escalate verb entirely. The cluster-admin " +
		"ClusterRole already has full RBAC privileges; no other role " +
		"should need escalate.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "escalate"},
	Scanner: "rbac.Escalate",
}

func RBACEscalate(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACEscalate, []string{"escalate"},
		"rbac.authorization.k8s.io", "roles", true), nil
}

var CheckRBACBind = core.Check{
	ID:           "k8s-rbac-bind",
	Title:        "Roles should not grant the bind verb on roles",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`bind` on roles/clusterroles lets the subject create " +
		"RoleBindings that reference roles broader than what the " +
		"subject itself holds. Like escalate, it bypasses RBAC's " +
		"privilege escalation prevention.",
	Remediation: "Limit bind to admin roles. For namespace-scoped admin " +
		"delegation, prefer dedicated admin ClusterRoles bound to " +
		"specific groups.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "bind"},
	Scanner: "rbac.Bind",
}

func RBACBind(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACBind, []string{"bind"},
		"rbac.authorization.k8s.io", "roles", true), nil
}

var CheckRBACCreatePods = core.Check{
	ID:           "k8s-rbac-create-pods",
	Title:        "Roles should rarely grant create on pods",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "Direct create on pods (as opposed to controllers like " +
		"Deployments) lets the subject schedule a pod with any " +
		"ServiceAccount they can name — including a powerful one in " +
		"the same namespace. It is a well-known privilege escalation " +
		"primitive in multi-tenant clusters.",
	Remediation: "Grant create on Deployments/StatefulSets instead and " +
		"let the controllers create the pods. If you must allow direct " +
		"pod creation (e.g. for a debug tool), pair the role with a " +
		"narrow `pods/serviceAccountName` admission policy.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.2"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "pods"},
	Scanner: "rbac.CreatePods",
}

func RBACCreatePods(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACCreatePods, []string{"create"},
		"", "pods", false), nil
}

var CheckRBACCSRApprove = core.Check{
	ID:           "k8s-rbac-csr-approve",
	Title:        "Roles should not grant approval on CertificateSigningRequests",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "The `update` verb on certificatesigningrequests/approval " +
		"lets the subject issue cluster-trusted certificates for any " +
		"identity. Combined with a kubelet bootstrap workflow, this " +
		"can lead directly to a node compromise.",
	Remediation: "Approval should be reserved for the controller-manager " +
		"and a small operator group. Audit and remove any other " +
		"binding to system:certificates.k8s.io:certificatesigningrequests/approval.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.24"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "certificates"},
	Scanner: "rbac.CSRApprove",
}

func RBACCSRApprove(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACCSRApprove, []string{"update", "*"},
		"certificates.k8s.io", "certificatesigningrequests/approval", true), nil
}

var CheckRBACTokenRequest = core.Check{
	ID:           "k8s-rbac-tokenrequest",
	Title:        "Roles should not grant create on serviceaccounts/token broadly",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`create` on serviceaccounts/token lets the subject " +
		"mint bound tokens for any ServiceAccount they can name, which " +
		"is most of the way to becoming that SA. The kube-controller-" +
		"manager needs this verb; almost nothing else does.",
	Remediation: "Restrict via `resourceNames: [<specific-sa>]` or " +
		"remove the verb entirely. Tools that need to issue tokens " +
		"should use `audience`-bound TokenRequest projection on a " +
		"workload SA rather than the create verb.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.5"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "tokens"},
	Scanner: "rbac.TokenRequest",
}

func RBACTokenRequest(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return verbResourceCheck(g, CheckRBACTokenRequest, []string{"create"},
		"", "serviceaccounts/token", false), nil
}

func init() {
	core.Register(CheckRBACSecretsRead, RBACSecretsRead)
	core.Register(CheckRBACSecretsWrite, RBACSecretsWrite)
	core.Register(CheckRBACPodsExec, RBACPodsExec)
	core.Register(CheckRBACPodsPortforward, RBACPodsPortforward)
	core.Register(CheckRBACImpersonate, RBACImpersonate)
	core.Register(CheckRBACEscalate, RBACEscalate)
	core.Register(CheckRBACBind, RBACBind)
	core.Register(CheckRBACCreatePods, RBACCreatePods)
	core.Register(CheckRBACCSRApprove, RBACCSRApprove)
	core.Register(CheckRBACTokenRequest, RBACTokenRequest)
}
