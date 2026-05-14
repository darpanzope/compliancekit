package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// rbacRoleTypes are the two role-bearing resource types in K8s RBAC.
// Every "role rule" check iterates both.
var rbacRoleTypes = []string{k8scol.RoleType, k8scol.ClusterRoleType}

// rbacBindingTypes are the two binding resource types.
var rbacBindingTypes = []string{k8scol.RoleBindingType, k8scol.ClusterRoleBindingType}

// ----- Wildcard verbs --------------------------------------------

var CheckRBACWildcardVerbs = core.Check{
	ID:           "k8s-rbac-wildcard-verbs",
	Title:        "Roles should not grant wildcard verbs",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "A rule with `verbs: ['*']` grants every action — get, " +
		"create, update, delete, patch, and watch — on the named " +
		"resources. Even when scoped to one resource type, this is " +
		"rarely the intent; usually one or two verbs are sufficient. " +
		"Wildcards make least-privilege analysis impossible.",
	Remediation: "Enumerate the verbs the role actually needs " +
		"(get/list/watch for read-only; add create/update/delete only " +
		"as required). Use `kubectl auth can-i --list --as=<sa>` to " +
		"validate the minimum.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.3"},
		"cis-v8":   {"6.1", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "wildcard", "least-privilege"},
	Scanner: "rbac.WildcardVerbs",
}

func RBACWildcardVerbs(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardVerbs, "verbs", "*"), nil
}

// ----- Wildcard resources ---------------------------------------

var CheckRBACWildcardResources = core.Check{
	ID:           "k8s-rbac-wildcard-resources",
	Title:        "Roles should not grant wildcard resources",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`resources: ['*']` grants the rule's verbs against " +
		"every resource type, present or future. Adding a new CRD " +
		"to the cluster silently extends the role's scope.",
	Remediation: "List exact resource names: `[pods, configmaps, services]`. " +
		"For CRDs, name them explicitly.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.1"},
	},
	Tags:    []string{"k8s", "rbac", "wildcard"},
	Scanner: "rbac.WildcardResources",
}

func RBACWildcardResources(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardResources, "resources", "*"), nil
}

// ----- Wildcard API groups ---------------------------------------

var CheckRBACWildcardAPIGroups = core.Check{
	ID:           "k8s-rbac-wildcard-apigroups",
	Title:        "Roles should not grant wildcard API groups",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "`apiGroups: ['*']` grants the rule's verbs across every " +
		"API group at once, including custom resources. Combined with " +
		"wildcard verbs or resources, this is effectively cluster-admin.",
	Remediation: "Enumerate API groups: `['', 'apps', 'batch', " +
		"'networking.k8s.io']` etc.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.1"},
	},
	Tags:    []string{"k8s", "rbac", "wildcard"},
	Scanner: "rbac.WildcardAPIGroups",
}

func RBACWildcardAPIGroups(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardAPIGroups, "api_groups", "*"), nil
}

// ----- Full wildcard (cluster-admin-equivalent) ------------------

var CheckRBACFullWildcard = core.Check{
	ID:           "k8s-rbac-full-wildcard",
	Title:        "Roles should not grant * verbs * resources * api groups simultaneously",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleType,
	Description: "A single rule with `*` in verbs, resources, AND " +
		"apiGroups is functionally identical to cluster-admin. It " +
		"grants every action on every resource type in every group, " +
		"present and future. This is the canonical privilege " +
		"escalation surface and should exist only on `cluster-admin` " +
		"itself.",
	Remediation: "Replace the wildcard rule with explicit grants. If a " +
		"workload genuinely needs cluster-admin, use the existing " +
		"`cluster-admin` ClusterRole and bind it explicitly so audit " +
		"trails make the intent visible.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.3"},
		"cis-v8":   {"6.1", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "cluster-admin", "critical"},
	Scanner: "rbac.FullWildcard",
}

func RBACFullWildcard(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, t := range rbacRoleTypes {
		for _, role := range g.ByType(t) {
			// cluster-admin itself is the only legitimate full-wildcard.
			if t == k8scol.ClusterRoleType && role.Name == "cluster-admin" {
				continue
			}
			rules, _ := role.Attributes["rules"].([]any)
			hit := false
			for _, ri := range rules {
				r, ok := ri.(map[string]any)
				if !ok {
					continue
				}
				if listContains(r["verbs"], "*") &&
					listContains(r["resources"], "*") &&
					listContains(r["api_groups"], "*") {
					hit = true
					break
				}
			}
			f := newRoleFinding(CheckRBACFullWildcard, role)
			if hit {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants * on all api groups / resources / verbs", roleKind(t), roleDesc(role))
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no full-wildcard rule", roleKind(t), roleDesc(role))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

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

// ----- Binding-level checks --------------------------------------

var CheckRBACClusterAdminBinding = core.Check{
	ID:           "k8s-rbac-cluster-admin-non-system",
	Title:        "ClusterRoleBindings to cluster-admin should target only system subjects",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleBindingType,
	Description: "A binding to the built-in `cluster-admin` ClusterRole " +
		"grants total cluster control. The default bindings shipped " +
		"with the kube-apiserver bind it to `system:masters` (the " +
		"in-cluster trust chain) and to specific control-plane " +
		"components — anything beyond that is a posture failure unless " +
		"a written justification exists.",
	Remediation: "Audit `kubectl get clusterrolebindings -o yaml | " +
		"grep -B5 cluster-admin`. For human admins, prefer a named " +
		"admin Group; bind that group to cluster-admin with explicit " +
		"subjects. Revoke ad-hoc cluster-admin bindings to individual " +
		"user accounts.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.3"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "cluster-admin", "critical"},
	Scanner: "rbac.ClusterAdminBinding",
}

func RBACClusterAdminBinding(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, crb := range g.ByType(k8scol.ClusterRoleBindingType) {
		roleName, _ := crb.Attributes["role_name"].(string)
		if roleName != "cluster-admin" {
			continue
		}
		nonSystem := []string{}
		subs, _ := crb.Attributes["subjects"].([]any)
		for _, si := range subs {
			s, ok := si.(map[string]any)
			if !ok {
				continue
			}
			name, _ := s["name"].(string)
			kind, _ := s["kind"].(string)
			ns, _ := s["namespace"].(string)
			if isSystemSubject(kind, name, ns) {
				continue
			}
			nonSystem = append(nonSystem, fmt.Sprintf("%s:%s", kind, name))
		}
		f := newBindingFinding(CheckRBACClusterAdminBinding, crb)
		if len(nonSystem) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("clusterrolebinding %q: cluster-admin bound only to system subjects", crb.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("clusterrolebinding %q: cluster-admin bound to non-system subjects: %s",
				crb.Name, strings.Join(nonSystem, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckRBACAnonymousBind = core.Check{
	ID:           "k8s-rbac-anonymous-bind",
	Title:        "Bindings should not grant any role to system:anonymous",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ClusterRoleBindingType,
	Description: "A binding that includes the user `system:anonymous` or " +
		"the group `system:unauthenticated` grants permissions to any " +
		"caller with network access to the API server, regardless of " +
		"authentication. This is a very common misconfiguration that " +
		"turns into a critical incident the moment the API server is " +
		"reachable from outside the cluster.",
	Remediation: "`kubectl get clusterrolebindings,rolebindings -A -o yaml " +
		"| grep -B5 -E 'system:(anonymous|unauthenticated)'`. Remove " +
		"or replace every match.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.2", "CC6.8"},
		"iso27001": {"A.5.15", "A.8.2", "A.8.3", "A.8.5"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "anonymous", "critical"},
	Scanner: "rbac.AnonymousBind",
}

func RBACAnonymousBind(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return bindingSubjectCheck(g, CheckRBACAnonymousBind,
		[]string{"system:anonymous", "system:unauthenticated"}), nil
}

var CheckRBACEmptySubjects = core.Check{
	ID:           "k8s-rbac-empty-subjects",
	Title:        "Bindings should have at least one subject",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.RoleBindingType,
	Description: "A binding with zero subjects is dead code — it cannot " +
		"grant access to anyone. Most often it is a leftover from a " +
		"removed account or group. Either delete it or document why it " +
		"exists as a placeholder.",
	Remediation: "`kubectl delete <kind> <name>` for any binding with " +
		"no subjects. If kept intentionally as a placeholder, add a " +
		"comment annotation explaining why.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"6.1"},
	},
	Tags:    []string{"k8s", "rbac", "hygiene"},
	Scanner: "rbac.EmptySubjects",
}

func RBACEmptySubjects(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, t := range rbacBindingTypes {
		for _, b := range g.ByType(t) {
			subs, _ := b.Attributes["subjects"].([]any)
			f := newBindingFinding(CheckRBACEmptySubjects, b)
			if len(subs) == 0 {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: no subjects", bindingKind(t), roleDesc(b))
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: %d subject(s)", bindingKind(t), roleDesc(b), len(subs))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

var CheckRBACStaleRoleRef = core.Check{
	ID:           "k8s-rbac-stale-role-ref",
	Title:        "Bindings should reference an existing role",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.RoleBindingType,
	Description: "A binding with a roleRef that does not resolve grants " +
		"no access — the API server silently drops it. The danger is " +
		"that a future role recreation may reactivate an unintended " +
		"grant. Delete or fix every stale binding.",
	Remediation: "Either delete the binding or create the referenced " +
		"role. `kubectl get rolebinding -A -o json | jq ...` filtering " +
		"on roleRef.name is the quick audit.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"6.1"},
	},
	Tags:    []string{"k8s", "rbac", "hygiene"},
	Scanner: "rbac.StaleRoleRef",
}

func RBACStaleRoleRef(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	clusterRoles := indexNames(g.ByType(k8scol.ClusterRoleType))
	rolesByNs := indexByNamespace(g.ByType(k8scol.RoleType))

	for _, b := range g.ByType(k8scol.RoleBindingType) {
		kind, _ := b.Attributes["role_kind"].(string)
		name, _ := b.Attributes["role_name"].(string)
		ns, _ := b.Attributes["namespace"].(string)
		f := newBindingFinding(CheckRBACStaleRoleRef, b)
		found := false
		switch kind {
		case "ClusterRole":
			_, found = clusterRoles[name]
		case "Role":
			_, found = rolesByNs[ns][name]
		}
		if found {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("rolebinding %q: roleRef resolves", roleDesc(b))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("rolebinding %q: %s/%s does not resolve", roleDesc(b), kind, name)
		}
		findings = append(findings, f)
	}
	for _, b := range g.ByType(k8scol.ClusterRoleBindingType) {
		kind, _ := b.Attributes["role_kind"].(string)
		name, _ := b.Attributes["role_name"].(string)
		f := newBindingFinding(CheckRBACStaleRoleRef, b)
		found := false
		if kind == "ClusterRole" {
			_, found = clusterRoles[name]
		}
		if found {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("clusterrolebinding %q: roleRef resolves", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("clusterrolebinding %q: %s/%s does not resolve", b.Name, kind, name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckRBACUserSubject = core.Check{
	ID:           "k8s-rbac-user-subject",
	Title:        "Bindings should target ServiceAccounts or Groups, not Users",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.RoleBindingType,
	Description: "Binding directly to a User makes lifecycle messy — " +
		"if the user leaves the org, the binding lingers and the audit " +
		"chain breaks. Groups are revocable centrally; ServiceAccounts " +
		"are namespace-scoped and rotatable. User subjects exist for " +
		"emergencies and one-offs.",
	Remediation: "Bind to a Group instead and manage membership in the " +
		"IdP. For automated callers, switch to a ServiceAccount.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.16", "A.5.18"},
		"cis-v8":   {"6.1", "6.2"},
	},
	Tags:    []string{"k8s", "rbac", "hygiene", "lifecycle"},
	Scanner: "rbac.UserSubject",
}

func RBACUserSubject(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, t := range rbacBindingTypes {
		for _, b := range g.ByType(t) {
			subs, _ := b.Attributes["subjects"].([]any)
			users := []string{}
			for _, si := range subs {
				s, ok := si.(map[string]any)
				if !ok {
					continue
				}
				kind, _ := s["kind"].(string)
				if kind == "User" {
					name, _ := s["name"].(string)
					users = append(users, name)
				}
			}
			f := newBindingFinding(CheckRBACUserSubject, b)
			if len(users) == 0 {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no User subjects", bindingKind(t), roleDesc(b))
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: User subjects: %s", bindingKind(t), roleDesc(b), strings.Join(users, ", "))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ----- shared helpers + init -------------------------------------

func init() {
	core.Register(CheckRBACWildcardVerbs, RBACWildcardVerbs)
	core.Register(CheckRBACWildcardResources, RBACWildcardResources)
	core.Register(CheckRBACWildcardAPIGroups, RBACWildcardAPIGroups)
	core.Register(CheckRBACFullWildcard, RBACFullWildcard)
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
	core.Register(CheckRBACClusterAdminBinding, RBACClusterAdminBinding)
	core.Register(CheckRBACAnonymousBind, RBACAnonymousBind)
	core.Register(CheckRBACEmptySubjects, RBACEmptySubjects)
	core.Register(CheckRBACStaleRoleRef, RBACStaleRoleRef)
	core.Register(CheckRBACUserSubject, RBACUserSubject)
}

// listContains reports whether the given attribute value (expected
// []string from copyStringSlice) contains target. Used by every
// wildcard check.
func listContains(v any, target string) bool {
	xs, _ := v.([]string)
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

// ruleAttrCheck handles the wildcard-on-single-attribute cases
// (verbs, resources, api_groups). It iterates roles + cluster roles
// and flags any rule whose named attribute contains wildcard.
func ruleAttrCheck(g *core.ResourceGraph, check core.Check, attr, wildcard string) []core.Finding {
	findings := []core.Finding{}
	for _, t := range rbacRoleTypes {
		for _, role := range g.ByType(t) {
			if isSystemRole(t, role.Name) {
				continue
			}
			rules, _ := role.Attributes["rules"].([]any)
			hit := false
			for _, ri := range rules {
				r, ok := ri.(map[string]any)
				if !ok {
					continue
				}
				if listContains(r[attr], wildcard) {
					hit = true
					break
				}
			}
			f := newRoleFinding(check, role)
			if hit {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule contains wildcard %s", roleKind(t), roleDesc(role), attr)
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no wildcard %s", roleKind(t), roleDesc(role), attr)
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// verbResourceCheck flags any role with a rule granting at least one
// of the named verbs on the named resource (in apiGroup ag). Used by
// every "dangerous specific permission" check.
//
// If requireMatch is true, the rule's apiGroups must include ag.
// If false, both "" core and "*" satisfy the apiGroups requirement.
func verbResourceCheck(g *core.ResourceGraph, check core.Check, verbs []string,
	ag, resource string, requireMatch bool) []core.Finding {
	findings := []core.Finding{}
	for _, t := range rbacRoleTypes {
		for _, role := range g.ByType(t) {
			if isSystemRole(t, role.Name) {
				continue
			}
			rules, _ := role.Attributes["rules"].([]any)
			hit := false
			for _, ri := range rules {
				r, ok := ri.(map[string]any)
				if !ok {
					continue
				}
				if !ruleMatchesResource(r, ag, resource, requireMatch) {
					continue
				}
				if anyVerbMatch(r["verbs"], verbs) {
					hit = true
					break
				}
			}
			f := newRoleFinding(check, role)
			if hit {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants %s on %s", roleKind(t), roleDesc(role),
					strings.Join(verbs, "/"), resourceLabel(ag, resource))
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no %s on %s",
					roleKind(t), roleDesc(role), strings.Join(verbs, "/"),
					resourceLabel(ag, resource))
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// ruleVerbCheck flags any role with any rule listing the target verb,
// regardless of resource. impersonate has no resource gate; this is
// the simpler primitive.
func ruleVerbCheck(g *core.ResourceGraph, check core.Check, targetVerb string) []core.Finding {
	findings := []core.Finding{}
	for _, t := range rbacRoleTypes {
		for _, role := range g.ByType(t) {
			if isSystemRole(t, role.Name) {
				continue
			}
			rules, _ := role.Attributes["rules"].([]any)
			hit := false
			for _, ri := range rules {
				r, ok := ri.(map[string]any)
				if !ok {
					continue
				}
				verbs, _ := r["verbs"].([]string)
				for _, v := range verbs {
					if v == targetVerb || v == "*" {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
			f := newRoleFinding(check, role)
			if hit {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants %q verb", roleKind(t), roleDesc(role), targetVerb)
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no %q verb", roleKind(t), roleDesc(role), targetVerb)
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func ruleMatchesResource(r map[string]any, ag, resource string, requireMatch bool) bool {
	resources, _ := r["resources"].([]string)
	apiGroups, _ := r["api_groups"].([]string)
	resMatch := false
	for _, x := range resources {
		if x == resource || x == "*" {
			resMatch = true
			break
		}
	}
	if !resMatch {
		return false
	}
	agMatch := false
	for _, x := range apiGroups {
		if x == ag || (!requireMatch && (x == "" || x == "*")) {
			agMatch = true
			break
		}
		if requireMatch && x == "*" {
			agMatch = true
			break
		}
	}
	return agMatch
}

func anyVerbMatch(verbs any, targets []string) bool {
	vs, _ := verbs.([]string)
	for _, v := range vs {
		for _, t := range targets {
			if v == t || v == "*" {
				return true
			}
		}
	}
	return false
}

func bindingSubjectCheck(g *core.ResourceGraph, check core.Check, targets []string) []core.Finding {
	findings := []core.Finding{}
	for _, t := range rbacBindingTypes {
		for _, b := range g.ByType(t) {
			subs, _ := b.Attributes["subjects"].([]any)
			matched := []string{}
			for _, si := range subs {
				s, ok := si.(map[string]any)
				if !ok {
					continue
				}
				name, _ := s["name"].(string)
				for _, tgt := range targets {
					if name == tgt {
						matched = append(matched, name)
					}
				}
			}
			f := newBindingFinding(check, b)
			if len(matched) > 0 {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("%s %q: targets %s", bindingKind(t), roleDesc(b), strings.Join(matched, ", "))
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("%s %q: no sensitive subjects", bindingKind(t), roleDesc(b))
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func newRoleFinding(check core.Check, role core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: role.Ref(),
		Tags:     check.Tags,
	}
}

func newBindingFinding(check core.Check, binding core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: binding.Ref(),
		Tags:     check.Tags,
	}
}

// roleKind / bindingKind render the human-readable kind for a finding
// message based on the resource type.
func roleKind(t string) string {
	if t == k8scol.ClusterRoleType {
		return "clusterrole"
	}
	return "role"
}

func bindingKind(t string) string {
	if t == k8scol.ClusterRoleBindingType {
		return "clusterrolebinding"
	}
	return "rolebinding"
}

// roleDesc renders "ns/name" for namespaced kinds or just name for
// cluster-scoped kinds.
func roleDesc(r core.Resource) string {
	ns, _ := r.Attributes["namespace"].(string)
	if ns == "" {
		return r.Name
	}
	return ns + "/" + r.Name
}

// isSystemRole excludes the built-in roles that legitimately need
// broad permissions (cluster-admin, system:*). Tracking these is
// noise; v0.11 focuses on operator-authored roles.
func isSystemRole(t, name string) bool {
	if t == k8scol.ClusterRoleType {
		if name == "cluster-admin" || strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "kubeadm:") {
			return true
		}
	}
	return false
}

// isSystemSubject reports whether the (kind, name, namespace) tuple
// is a built-in K8s identity. The cluster-admin bindings the API
// server ships with target system:masters and related groups.
func isSystemSubject(kind, name, namespace string) bool {
	if strings.HasPrefix(name, "system:") {
		return true
	}
	if kind == "ServiceAccount" && (namespace == "kube-system" || namespace == "kube-public") {
		return true
	}
	return false
}

func resourceLabel(ag, resource string) string {
	if ag == "" {
		return resource
	}
	return ag + "/" + resource
}

// indexNames builds a name->resource lookup for cluster-scoped roles.
func indexNames(rs []core.Resource) map[string]core.Resource {
	out := map[string]core.Resource{}
	for _, r := range rs {
		out[r.Name] = r
	}
	return out
}

// indexByNamespace builds a ns->name->resource lookup for namespaced
// roles.
func indexByNamespace(rs []core.Resource) map[string]map[string]core.Resource {
	out := map[string]map[string]core.Resource{}
	for _, r := range rs {
		ns, _ := r.Attributes["namespace"].(string)
		if out[ns] == nil {
			out[ns] = map[string]core.Resource{}
		}
		out[ns][r.Name] = r
	}
	return out
}
