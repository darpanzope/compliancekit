package k8s

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// collectCluster fetches Namespaces (cluster-scoped), ResourceQuotas,
// LimitRanges, ValidatingWebhookConfigurations, and
// MutatingWebhookConfigurations. The cluster-level posture surface.
func (c *Collector) collectCluster(ctx context.Context, scope *ContextScope) ([]core.Resource, error) {
	out := make([]core.Resource, 0, 32)

	nss, err := scope.Client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	for i := range nss.Items {
		ns := &nss.Items[i]
		if contains(scope.ExcludeNamespaces, ns.Name) {
			continue
		}
		out = append(out, c.namespaceResource(scope, ns))
	}

	rqs, err := listResourceQuotas(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list resourcequotas: %w", err)
	}
	for i := range rqs {
		out = append(out, c.resourceQuotaResource(scope, &rqs[i]))
	}

	lrs, err := listLimitRanges(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list limitranges: %w", err)
	}
	for i := range lrs {
		out = append(out, c.limitRangeResource(scope, &lrs[i]))
	}

	vwcs, err := scope.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list validatingwebhooks: %w", err)
	}
	for i := range vwcs.Items {
		out = append(out, c.validatingWebhookResource(scope, &vwcs.Items[i]))
	}

	mwcs, err := scope.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list mutatingwebhooks: %w", err)
	}
	for i := range mwcs.Items {
		out = append(out, c.mutatingWebhookResource(scope, &mwcs.Items[i]))
	}

	return out, nil
}

func listResourceQuotas(ctx context.Context, scope *ContextScope) ([]corev1.ResourceQuota, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterRQByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.ResourceQuota, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterRQByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterRQByExclude(in []corev1.ResourceQuota, ex []string) []corev1.ResourceQuota {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.ResourceQuota, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listLimitRanges(ctx context.Context, scope *ContextScope) ([]corev1.LimitRange, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterLRByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.LimitRange, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterLRByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterLRByExclude(in []corev1.LimitRange, ex []string) []corev1.LimitRange {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.LimitRange, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

// ---- Resource builders ----

func (c *Collector) namespaceResource(scope *ContextScope, ns *corev1.Namespace) core.Resource {
	psaEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]
	psaAudit := ns.Labels["pod-security.kubernetes.io/audit"]
	psaWarn := ns.Labels["pod-security.kubernetes.io/warn"]
	attrs := map[string]any{
		"phase":       string(ns.Status.Phase),
		"psa_enforce": psaEnforce,
		"psa_audit":   psaAudit,
		"psa_warn":    psaWarn,
		"labels":      copyStringMap(ns.Labels),
		"annotations": copyStringMap(ns.Annotations),
		"is_system":   isSystemNamespaceK8s(ns.Name),
		"finalizers":  namespaceFinalizers(ns),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", NamespaceType, scope.Name, ns.Name),
		Type:       NamespaceType,
		Name:       ns.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) resourceQuotaResource(scope *ContextScope, rq *corev1.ResourceQuota) core.Resource {
	hard := map[string]string{}
	for k, v := range rq.Spec.Hard {
		hard[string(k)] = v.String()
	}
	attrs := map[string]any{
		"namespace":   rq.Namespace,
		"hard":        hard,
		"hard_keys":   keysOfStringMap(hard),
		"has_pods":    keyPresent(hard, "pods"),
		"has_cpu":     keyPresentAny(hard, "limits.cpu", "requests.cpu"),
		"has_memory":  keyPresentAny(hard, "limits.memory", "requests.memory"),
		"has_objects": keyPresentAny(hard, "count/configmaps", "count/secrets", "persistentvolumeclaims"),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", ResourceQuotaType, scope.Name, rq.Namespace, rq.Name),
		Type:       ResourceQuotaType,
		Name:       rq.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) limitRangeResource(scope *ContextScope, lr *corev1.LimitRange) core.Resource {
	hasContainerDefaults := false
	for _, lim := range lr.Spec.Limits {
		if lim.Type == corev1.LimitTypeContainer {
			if len(lim.Default) > 0 || len(lim.DefaultRequest) > 0 {
				hasContainerDefaults = true
				break
			}
		}
	}
	attrs := map[string]any{
		"namespace":              lr.Namespace,
		"has_container_defaults": hasContainerDefaults,
		"limit_count":            len(lr.Spec.Limits),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", LimitRangeType, scope.Name, lr.Namespace, lr.Name),
		Type:       LimitRangeType,
		Name:       lr.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) validatingWebhookResource(scope *ContextScope, w *admissionregistrationv1.ValidatingWebhookConfiguration) core.Resource {
	webhooks := flattenValidatingWebhooks(w.Webhooks)
	attrs := map[string]any{
		"webhook_count":     len(w.Webhooks),
		"webhooks":          webhooks,
		"has_ignore_policy": webhooksHaveFailurePolicy(webhooks, "Ignore"),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", ValidatingWebhookConfigType, scope.Name, w.Name),
		Type:       ValidatingWebhookConfigType,
		Name:       w.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) mutatingWebhookResource(scope *ContextScope, w *admissionregistrationv1.MutatingWebhookConfiguration) core.Resource {
	webhooks := flattenMutatingWebhooks(w.Webhooks)
	attrs := map[string]any{
		"webhook_count":     len(w.Webhooks),
		"webhooks":          webhooks,
		"has_ignore_policy": webhooksHaveFailurePolicy(webhooks, "Ignore"),
		"has_side_effects":  webhooksHaveSideEffects(webhooks),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", MutatingWebhookConfigType, scope.Name, w.Name),
		Type:       MutatingWebhookConfigType,
		Name:       w.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

// ---- Helpers ----

// isSystemNamespaceK8s mirrors the checks-side isSystemNamespace
// helper but lives in the collector so the attribute is computed at
// collection time. Kept in sync with the checks-side helper.
func isSystemNamespaceK8s(name string) bool {
	switch name {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func namespaceFinalizers(ns *corev1.Namespace) []string {
	out := make([]string, 0, len(ns.Spec.Finalizers))
	for _, f := range ns.Spec.Finalizers {
		out = append(out, string(f))
	}
	return out
}

func keyPresent(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}

func keyPresentAny(m map[string]string, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func keysOfStringMap(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func flattenValidatingWebhooks(ws []admissionregistrationv1.ValidatingWebhook) []any {
	out := make([]any, 0, len(ws))
	for _, w := range ws {
		failurePolicy := ""
		if w.FailurePolicy != nil {
			failurePolicy = string(*w.FailurePolicy)
		}
		nsSelector := false
		if w.NamespaceSelector != nil {
			nsSelector = len(w.NamespaceSelector.MatchLabels) > 0 || len(w.NamespaceSelector.MatchExpressions) > 0
		}
		out = append(out, map[string]any{
			"name":            w.Name,
			"failure_policy":  failurePolicy,
			"has_ns_selector": nsSelector,
			"timeout_seconds": int32Or(w.TimeoutSeconds, 10),
			"side_effects":    sideEffectsString(w.SideEffects),
		})
	}
	return out
}

func flattenMutatingWebhooks(ws []admissionregistrationv1.MutatingWebhook) []any {
	out := make([]any, 0, len(ws))
	for _, w := range ws {
		failurePolicy := ""
		if w.FailurePolicy != nil {
			failurePolicy = string(*w.FailurePolicy)
		}
		nsSelector := false
		if w.NamespaceSelector != nil {
			nsSelector = len(w.NamespaceSelector.MatchLabels) > 0 || len(w.NamespaceSelector.MatchExpressions) > 0
		}
		out = append(out, map[string]any{
			"name":            w.Name,
			"failure_policy":  failurePolicy,
			"has_ns_selector": nsSelector,
			"timeout_seconds": int32Or(w.TimeoutSeconds, 10),
			"side_effects":    sideEffectsString(w.SideEffects),
		})
	}
	return out
}

func sideEffectsString(s *admissionregistrationv1.SideEffectClass) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func webhooksHaveFailurePolicy(webhooks []any, policy string) bool {
	for _, wi := range webhooks {
		w, ok := wi.(map[string]any)
		if !ok {
			continue
		}
		fp, _ := w["failure_policy"].(string)
		if fp == policy {
			return true
		}
	}
	return false
}

func webhooksHaveSideEffects(webhooks []any) bool {
	for _, wi := range webhooks {
		w, ok := wi.(map[string]any)
		if !ok {
			continue
		}
		se, _ := w["side_effects"].(string)
		if se != "" && se != "None" && se != "NoneOnDryRun" {
			return true
		}
	}
	return false
}
