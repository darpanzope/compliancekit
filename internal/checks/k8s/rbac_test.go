package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkClusterRole(name string, rules []any) core.Resource {
	return core.Resource{
		ID:       "k8s.clusterrole.prod." + name,
		Type:     k8scol.ClusterRoleType,
		Name:     name,
		Provider: "kubernetes",
		Attributes: map[string]any{
			"rules": rules,
		},
	}
}

func mkRole(ns, name string, rules []any) core.Resource {
	return core.Resource{
		ID:       "k8s.role.prod." + ns + "." + name,
		Type:     k8scol.RoleType,
		Name:     name,
		Provider: "kubernetes",
		Attributes: map[string]any{
			"namespace": ns,
			"rules":     rules,
		},
	}
}

func mkRule(verbs, resources, apiGroups []string) map[string]any {
	return map[string]any{
		"verbs":      verbs,
		"resources":  resources,
		"api_groups": apiGroups,
	}
}

func mkClusterRoleBinding(name, roleName string, subjects []any) core.Resource {
	return core.Resource{
		ID:       "k8s.crb.prod." + name,
		Type:     k8scol.ClusterRoleBindingType,
		Name:     name,
		Provider: "kubernetes",
		Attributes: map[string]any{
			"role_kind": "ClusterRole",
			"role_name": roleName,
			"subjects":  subjects,
		},
	}
}

func mkRoleBinding(ns, name, roleKind, roleName string, subjects []any) core.Resource {
	return core.Resource{
		ID:       "k8s.rb.prod." + ns + "." + name,
		Type:     k8scol.RoleBindingType,
		Name:     name,
		Provider: "kubernetes",
		Attributes: map[string]any{
			"namespace": ns,
			"role_kind": roleKind,
			"role_name": roleName,
			"subjects":  subjects,
		},
	}
}

func subj(kind, name, ns string) map[string]any {
	return map[string]any{"kind": kind, "name": name, "namespace": ns}
}

func TestRBACWildcards(t *testing.T) {
	g := newPodGraph(
		mkClusterRole("good", []any{mkRule([]string{"get"}, []string{"pods"}, []string{""})}),
		mkClusterRole("wild-verb", []any{mkRule([]string{"*"}, []string{"pods"}, []string{""})}),
		mkClusterRole("wild-res", []any{mkRule([]string{"get"}, []string{"*"}, []string{""})}),
		mkClusterRole("wild-ag", []any{mkRule([]string{"get"}, []string{"pods"}, []string{"*"})}),
		mkClusterRole("full-wild", []any{mkRule([]string{"*"}, []string{"*"}, []string{"*"})}),
		mkClusterRole("cluster-admin", []any{mkRule([]string{"*"}, []string{"*"}, []string{"*"})}),
	)
	v := runCheck(t, RBACWildcardVerbs, g)
	r := runCheck(t, RBACWildcardResources, g)
	a := runCheck(t, RBACWildcardAPIGroups, g)
	full := runCheck(t, RBACFullWildcard, g)
	if v["good"] != core.StatusPass || v["wild-verb"] != core.StatusFail {
		t.Errorf("verbs: %v", v)
	}
	if r["wild-res"] != core.StatusFail {
		t.Errorf("resources: %v", r)
	}
	if a["wild-ag"] != core.StatusFail {
		t.Errorf("apigroups: %v", a)
	}
	if full["full-wild"] != core.StatusFail {
		t.Errorf("full: %v", full)
	}
	// cluster-admin is exempt.
	if _, ok := full["cluster-admin"]; ok {
		t.Errorf("cluster-admin should be exempt from full-wildcard check")
	}
}

func TestRBACSystemRolesExempt(t *testing.T) {
	g := newPodGraph(
		mkClusterRole("system:masters", []any{mkRule([]string{"*"}, []string{"pods"}, []string{""})}),
	)
	v := runCheck(t, RBACWildcardVerbs, g)
	if _, ok := v["system:masters"]; ok {
		t.Errorf("system: roles should be exempt: %v", v)
	}
}

func TestRBACSecrets(t *testing.T) {
	g := newPodGraph(
		mkClusterRole("reader", []any{mkRule([]string{"get", "list", "watch"}, []string{"secrets"}, []string{""})}),
		mkClusterRole("writer", []any{mkRule([]string{"create", "update"}, []string{"secrets"}, []string{""})}),
		mkClusterRole("neither", []any{mkRule([]string{"get"}, []string{"configmaps"}, []string{""})}),
	)
	rd := runCheck(t, RBACSecretsRead, g)
	wr := runCheck(t, RBACSecretsWrite, g)
	if rd["reader"] != core.StatusFail || rd["neither"] != core.StatusPass {
		t.Errorf("read: %v", rd)
	}
	if wr["writer"] != core.StatusFail || wr["reader"] != core.StatusPass {
		t.Errorf("write: %v", wr)
	}
}

func TestRBACDangerousVerbs(t *testing.T) {
	g := newPodGraph(
		mkClusterRole("exec", []any{mkRule([]string{"create"}, []string{"pods/exec"}, []string{""})}),
		mkClusterRole("portfwd", []any{mkRule([]string{"create"}, []string{"pods/portforward"}, []string{""})}),
		mkClusterRole("imp", []any{mkRule([]string{"impersonate"}, []string{"users"}, []string{""})}),
		mkClusterRole("esc", []any{mkRule([]string{"escalate"}, []string{"roles"}, []string{"rbac.authorization.k8s.io"})}),
		mkClusterRole("bind-verb", []any{mkRule([]string{"bind"}, []string{"roles"}, []string{"rbac.authorization.k8s.io"})}),
		mkClusterRole("create-pods", []any{mkRule([]string{"create"}, []string{"pods"}, []string{""})}),
		mkClusterRole("csr", []any{mkRule([]string{"update"}, []string{"certificatesigningrequests/approval"}, []string{"certificates.k8s.io"})}),
		mkClusterRole("token", []any{mkRule([]string{"create"}, []string{"serviceaccounts/token"}, []string{""})}),
		mkClusterRole("clean", []any{mkRule([]string{"get"}, []string{"configmaps"}, []string{""})}),
	)
	ex := runCheck(t, RBACPodsExec, g)
	pf := runCheck(t, RBACPodsPortforward, g)
	im := runCheck(t, RBACImpersonate, g)
	es := runCheck(t, RBACEscalate, g)
	bn := runCheck(t, RBACBind, g)
	cp := runCheck(t, RBACCreatePods, g)
	cs := runCheck(t, RBACCSRApprove, g)
	tk := runCheck(t, RBACTokenRequest, g)
	cases := []struct {
		name   string
		got    map[string]core.Status
		failOn string
	}{
		{"exec", ex, "exec"}, {"portfwd", pf, "portfwd"}, {"impersonate", im, "imp"},
		{"escalate", es, "esc"}, {"bind", bn, "bind-verb"}, {"create-pods", cp, "create-pods"},
		{"csr", cs, "csr"}, {"token", tk, "token"},
	}
	for _, c := range cases {
		if c.got[c.failOn] != core.StatusFail {
			t.Errorf("%s: %s=%v (want fail)", c.name, c.failOn, c.got[c.failOn])
		}
		if c.got["clean"] != core.StatusPass {
			t.Errorf("%s: clean=%v (want pass)", c.name, c.got["clean"])
		}
	}
}

func TestRBACClusterAdminBinding(t *testing.T) {
	g := newPodGraph(
		mkClusterRoleBinding("system", "cluster-admin", []any{subj("Group", "system:masters", "")}),
		mkClusterRoleBinding("rogue", "cluster-admin", []any{subj("User", "darpan", "")}),
		mkClusterRoleBinding("kube-sys", "cluster-admin", []any{subj("ServiceAccount", "controller", "kube-system")}),
		mkClusterRoleBinding("not-admin", "view", []any{subj("User", "darpan", "")}),
	)
	got := runCheck(t, RBACClusterAdminBinding, g)
	if got["system"] != core.StatusPass || got["kube-sys"] != core.StatusPass {
		t.Errorf("system/kube-sys: %v / %v", got["system"], got["kube-sys"])
	}
	if got["rogue"] != core.StatusFail {
		t.Errorf("rogue: %v", got["rogue"])
	}
	if _, ok := got["not-admin"]; ok {
		t.Errorf("not-admin should not appear (not bound to cluster-admin)")
	}
}

func TestRBACAnonymousBind(t *testing.T) {
	g := newPodGraph(
		mkClusterRoleBinding("good", "view", []any{subj("User", "darpan", "")}),
		mkClusterRoleBinding("anon", "view", []any{subj("User", "system:anonymous", "")}),
		mkClusterRoleBinding("unauth", "view", []any{subj("Group", "system:unauthenticated", "")}),
	)
	got := runCheck(t, RBACAnonymousBind, g)
	if got["good"] != core.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["anon"] != core.StatusFail || got["unauth"] != core.StatusFail {
		t.Errorf("anon/unauth: %v / %v", got["anon"], got["unauth"])
	}
}

func TestRBACEmptySubjects(t *testing.T) {
	g := newPodGraph(
		mkClusterRoleBinding("filled", "view", []any{subj("User", "darpan", "")}),
		mkClusterRoleBinding("empty", "view", []any{}),
	)
	got := runCheck(t, RBACEmptySubjects, g)
	if got["filled"] != core.StatusPass || got["empty"] != core.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestRBACStaleRoleRef(t *testing.T) {
	g := newPodGraph(
		mkClusterRole("real-cr", []any{}),
		mkRole("default", "real-role", []any{}),
		mkClusterRoleBinding("good-crb", "real-cr", []any{}),
		mkClusterRoleBinding("stale-crb", "ghost", []any{}),
		mkRoleBinding("default", "good-rb", "Role", "real-role", []any{}),
		mkRoleBinding("default", "stale-rb", "Role", "ghost", []any{}),
	)
	got := runCheck(t, RBACStaleRoleRef, g)
	if got["good-crb"] != core.StatusPass || got["good-rb"] != core.StatusPass {
		t.Errorf("good: %v", got)
	}
	if got["stale-crb"] != core.StatusFail || got["stale-rb"] != core.StatusFail {
		t.Errorf("stale: %v", got)
	}
}

func TestRBACUserSubject(t *testing.T) {
	g := newPodGraph(
		mkClusterRoleBinding("sa", "view", []any{subj("ServiceAccount", "x", "default")}),
		mkClusterRoleBinding("group", "view", []any{subj("Group", "admins", "")}),
		mkClusterRoleBinding("user", "view", []any{subj("User", "darpan", "")}),
	)
	got := runCheck(t, RBACUserSubject, g)
	if got["sa"] != core.StatusPass || got["group"] != core.StatusPass {
		t.Errorf("sa/group: %v / %v", got["sa"], got["group"])
	}
	if got["user"] != core.StatusFail {
		t.Errorf("user: %v", got["user"])
	}
}
