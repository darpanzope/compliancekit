package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// rbacRoleTypes are the two role-bearing resource types in K8s RBAC.
// Every "role rule" check iterates both.
var rbacRoleTypes = []string{k8scol.RoleType, k8scol.ClusterRoleType}

// rbacBindingTypes are the two binding resource types.
var rbacBindingTypes = []string{k8scol.RoleBindingType, k8scol.ClusterRoleBindingType}

// ----- Wildcard verbs --------------------------------------------

var CheckRBACWildcardVerbs = compliancekit.Check{
	ID:           "k8s-rbac-wildcard-verbs",
	Title:        "Roles should not grant wildcard verbs",
	Severity:     compliancekit.SeverityHigh,
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

func RBACWildcardVerbs(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardVerbs, "verbs", "*"), nil
}

// ----- Wildcard resources ---------------------------------------

var CheckRBACWildcardResources = compliancekit.Check{
	ID:           "k8s-rbac-wildcard-resources",
	Title:        "Roles should not grant wildcard resources",
	Severity:     compliancekit.SeverityHigh,
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

func RBACWildcardResources(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardResources, "resources", "*"), nil
}

// ----- Wildcard API groups ---------------------------------------

var CheckRBACWildcardAPIGroups = compliancekit.Check{
	ID:           "k8s-rbac-wildcard-apigroups",
	Title:        "Roles should not grant wildcard API groups",
	Severity:     compliancekit.SeverityMedium,
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

func RBACWildcardAPIGroups(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ruleAttrCheck(g, CheckRBACWildcardAPIGroups, "api_groups", "*"), nil
}

// ----- Full wildcard (cluster-admin-equivalent) ------------------

var CheckRBACFullWildcard = compliancekit.Check{
	ID:           "k8s-rbac-full-wildcard",
	Title:        "Roles should not grant * verbs * resources * api groups simultaneously",
	Severity:     compliancekit.SeverityCritical,
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

func RBACFullWildcard(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
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
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants * on all api groups / resources / verbs", roleKind(t), roleDesc(role))
			} else {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("%s %q: no full-wildcard rule", roleKind(t), roleDesc(role))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ----- shared helpers + init -------------------------------------

func init() {
	compliancekit.Register(CheckRBACWildcardVerbs, RBACWildcardVerbs)
	compliancekit.Register(CheckRBACWildcardResources, RBACWildcardResources)
	compliancekit.Register(CheckRBACWildcardAPIGroups, RBACWildcardAPIGroups)
	compliancekit.Register(CheckRBACFullWildcard, RBACFullWildcard)
	// v0.22 phase 1 — verb-based dangerous-action checks moved to
	// rbac_roles.go; binding-level checks moved to rbac_bindings.go.
	// Each split file owns its own init() registering its checks so
	// the registry call sites stay near their definitions.
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
func ruleAttrCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, attr, wildcard string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
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
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule contains wildcard %s", roleKind(t), roleDesc(role), attr)
			} else {
				f.Status = compliancekit.StatusPass
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
func verbResourceCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, verbs []string,
	ag, resource string, requireMatch bool) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
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
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants %s on %s", roleKind(t), roleDesc(role),
					strings.Join(verbs, "/"), resourceLabel(ag, resource))
			} else {
				f.Status = compliancekit.StatusPass
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
func ruleVerbCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, targetVerb string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
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
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("%s %q: rule grants %q verb", roleKind(t), roleDesc(role), targetVerb)
			} else {
				f.Status = compliancekit.StatusPass
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

func bindingSubjectCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, targets []string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
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
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("%s %q: targets %s", bindingKind(t), roleDesc(b), strings.Join(matched, ", "))
			} else {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("%s %q: no sensitive subjects", bindingKind(t), roleDesc(b))
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func newRoleFinding(check compliancekit.Check, role compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: role.Ref(),
		Tags:     check.Tags,
	}
}

func newBindingFinding(check compliancekit.Check, binding compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
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
func roleDesc(r compliancekit.Resource) string {
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
func indexNames(rs []compliancekit.Resource) map[string]compliancekit.Resource {
	out := map[string]compliancekit.Resource{}
	for _, r := range rs {
		out[r.Name] = r
	}
	return out
}

// indexByNamespace builds a ns->name->resource lookup for namespaced
// roles.
func indexByNamespace(rs []compliancekit.Resource) map[string]map[string]compliancekit.Resource {
	out := map[string]map[string]compliancekit.Resource{}
	for _, r := range rs {
		ns, _ := r.Attributes["namespace"].(string)
		if out[ns] == nil {
			out[ns] = map[string]compliancekit.Resource{}
		}
		out[ns][r.Name] = r
	}
	return out
}
