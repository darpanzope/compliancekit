package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 1 — binding-level RBAC checks split out of rbac.go
// (1045 → 3 files) to satisfy the 600-LoC invariant. Operates on the
// k8s.{role,cluster_role}binding resources rather than the role
// rules themselves.
//
// 5 checks total — cluster-admin binding sanity, anonymous bind
// detection, empty/stale roleRef hygiene, and User-vs-Group-vs-SA
// subject preference.

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

func init() {
	core.Register(CheckRBACClusterAdminBinding, RBACClusterAdminBinding)
	core.Register(CheckRBACAnonymousBind, RBACAnonymousBind)
	core.Register(CheckRBACEmptySubjects, RBACEmptySubjects)
	core.Register(CheckRBACStaleRoleRef, RBACStaleRoleRef)
	core.Register(CheckRBACUserSubject, RBACUserSubject)
}
