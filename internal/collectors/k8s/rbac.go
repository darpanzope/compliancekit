package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// collectRBAC fetches every RBAC primitive plus ServiceAccounts.
// Roles/RoleBindings/SAs are namespaced; ClusterRoles/ClusterRoleBindings
// are cluster-scoped. The check pack inspects rules + subjects against
// flattened attribute maps so check code stays free of client-go.
func (c *Collector) collectRBAC(ctx context.Context, scope *ContextScope) ([]core.Resource, error) {
	out := make([]core.Resource, 0, 64)

	crs, err := scope.Client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	for i := range crs.Items {
		out = append(out, c.clusterRoleResource(scope, &crs.Items[i]))
	}

	crbs, err := scope.Client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	for i := range crbs.Items {
		out = append(out, c.clusterRoleBindingResource(scope, &crbs.Items[i]))
	}

	roles, err := listRoles(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	for i := range roles {
		out = append(out, c.roleResource(scope, &roles[i]))
	}

	rbs, err := listRoleBindings(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	for i := range rbs {
		out = append(out, c.roleBindingResource(scope, &rbs[i]))
	}

	sas, err := listServiceAccounts(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	for i := range sas {
		out = append(out, c.serviceAccountResource(scope, &sas[i]))
	}

	return out, nil
}

func listRoles(ctx context.Context, scope *ContextScope) ([]rbacv1.Role, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterRolesByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]rbacv1.Role, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterRolesByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterRolesByExclude(in []rbacv1.Role, ex []string) []rbacv1.Role {
	if len(ex) == 0 {
		return in
	}
	out := make([]rbacv1.Role, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listRoleBindings(ctx context.Context, scope *ContextScope) ([]rbacv1.RoleBinding, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterRoleBindingsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]rbacv1.RoleBinding, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterRoleBindingsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterRoleBindingsByExclude(in []rbacv1.RoleBinding, ex []string) []rbacv1.RoleBinding {
	if len(ex) == 0 {
		return in
	}
	out := make([]rbacv1.RoleBinding, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listServiceAccounts(ctx context.Context, scope *ContextScope) ([]corev1.ServiceAccount, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterSAByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.ServiceAccount, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterSAByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterSAByExclude(in []corev1.ServiceAccount, ex []string) []corev1.ServiceAccount {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.ServiceAccount, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

// ---- Resource builders ----

func (c *Collector) clusterRoleResource(scope *ContextScope, cr *rbacv1.ClusterRole) core.Resource {
	attrs := map[string]any{
		"rules":                flattenPolicyRules(cr.Rules),
		"has_aggregation_rule": cr.AggregationRule != nil,
		"labels":               copyStringMap(cr.Labels),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", ClusterRoleType, scope.Name, cr.Name),
		Type:       ClusterRoleType,
		Name:       cr.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) clusterRoleBindingResource(scope *ContextScope, crb *rbacv1.ClusterRoleBinding) core.Resource {
	attrs := map[string]any{
		"role_kind":      crb.RoleRef.Kind,
		"role_name":      crb.RoleRef.Name,
		"role_api_group": crb.RoleRef.APIGroup,
		"subjects":       flattenSubjects(crb.Subjects),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", ClusterRoleBindingType, scope.Name, crb.Name),
		Type:       ClusterRoleBindingType,
		Name:       crb.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) roleResource(scope *ContextScope, role *rbacv1.Role) core.Resource {
	attrs := map[string]any{
		"namespace": role.Namespace,
		"rules":     flattenPolicyRules(role.Rules),
		"labels":    copyStringMap(role.Labels),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", RoleType, scope.Name, role.Namespace, role.Name),
		Type:       RoleType,
		Name:       role.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) roleBindingResource(scope *ContextScope, rb *rbacv1.RoleBinding) core.Resource {
	attrs := map[string]any{
		"namespace":      rb.Namespace,
		"role_kind":      rb.RoleRef.Kind,
		"role_name":      rb.RoleRef.Name,
		"role_api_group": rb.RoleRef.APIGroup,
		"subjects":       flattenSubjects(rb.Subjects),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", RoleBindingType, scope.Name, rb.Namespace, rb.Name),
		Type:       RoleBindingType,
		Name:       rb.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) serviceAccountResource(scope *ContextScope, sa *corev1.ServiceAccount) core.Resource {
	attrs := map[string]any{
		"namespace":               sa.Namespace,
		"automount_token":         automountValue(sa.AutomountServiceAccountToken),
		"image_pull_secret_count": len(sa.ImagePullSecrets),
		"secret_count":            len(sa.Secrets),
		"labels":                  copyStringMap(sa.Labels),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", ServiceAccountType, scope.Name, sa.Namespace, sa.Name),
		Type:       ServiceAccountType,
		Name:       sa.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

// ---- Flatteners ----

func flattenPolicyRules(rules []rbacv1.PolicyRule) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, map[string]any{
			"api_groups":        copyStringSlice(r.APIGroups),
			"resources":         copyStringSlice(r.Resources),
			"resource_names":    copyStringSlice(r.ResourceNames),
			"verbs":             copyStringSlice(r.Verbs),
			"non_resource_urls": copyStringSlice(r.NonResourceURLs),
		})
	}
	return out
}

func flattenSubjects(subs []rbacv1.Subject) []any {
	out := make([]any, 0, len(subs))
	for _, s := range subs {
		out = append(out, map[string]any{
			"kind":      s.Kind,
			"name":      s.Name,
			"namespace": s.Namespace,
			"api_group": s.APIGroup,
		})
	}
	return out
}

func copyStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
