package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// collectNetwork fetches Services, Ingresses, and NetworkPolicies.
// Pod-network exposure plus Ingress fronting plus the policy layer
// that controls them are the K8s network attack surface.
func (c *Collector) collectNetwork(ctx context.Context, scope *ContextScope) ([]compliancekit.Resource, error) {
	out := make([]compliancekit.Resource, 0, 32)

	svcs, err := listServices(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	for i := range svcs {
		out = append(out, c.serviceResource(scope, &svcs[i]))
	}

	ings, err := listIngresses(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}
	for i := range ings {
		out = append(out, c.ingressResource(scope, &ings[i]))
	}

	nps, err := listNetworkPolicies(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	for i := range nps {
		out = append(out, c.networkPolicyResource(scope, &nps[i]))
	}

	return out, nil
}

func listServices(ctx context.Context, scope *ContextScope) ([]corev1.Service, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterServicesByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.Service, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterServicesByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterServicesByExclude(in []corev1.Service, ex []string) []corev1.Service {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.Service, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listIngresses(ctx context.Context, scope *ContextScope) ([]networkingv1.Ingress, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterIngressesByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]networkingv1.Ingress, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterIngressesByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterIngressesByExclude(in []networkingv1.Ingress, ex []string) []networkingv1.Ingress {
	if len(ex) == 0 {
		return in
	}
	out := make([]networkingv1.Ingress, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listNetworkPolicies(ctx context.Context, scope *ContextScope) ([]networkingv1.NetworkPolicy, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterNPsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]networkingv1.NetworkPolicy, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterNPsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterNPsByExclude(in []networkingv1.NetworkPolicy, ex []string) []networkingv1.NetworkPolicy {
	if len(ex) == 0 {
		return in
	}
	out := make([]networkingv1.NetworkPolicy, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

// ---- Resource builders ----

func (c *Collector) serviceResource(scope *ContextScope, s *corev1.Service) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":                   s.Namespace,
		"type":                        string(s.Spec.Type),
		"external_ips":                copyStringSlice(s.Spec.ExternalIPs),
		"load_balancer_source_ranges": copyStringSlice(s.Spec.LoadBalancerSourceRanges),
		"ports":                       flattenServicePorts(s.Spec.Ports),
		"selector_labels":             copyStringMap(s.Spec.Selector),
		"cluster_ip":                  s.Spec.ClusterIP,
		"labels":                      copyStringMap(s.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", ServiceType, scope.Name, s.Namespace, s.Name),
		Type:       ServiceType,
		Name:       s.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) ingressResource(scope *ContextScope, ing *networkingv1.Ingress) compliancekit.Resource {
	hasTLS := len(ing.Spec.TLS) > 0
	hasDefaultBackend := ing.Spec.DefaultBackend != nil
	ingressClass := ""
	if ing.Spec.IngressClassName != nil {
		ingressClass = *ing.Spec.IngressClassName
	}
	attrs := map[string]any{
		"namespace":           ing.Namespace,
		"ingress_class":       ingressClass,
		"has_tls":             hasTLS,
		"has_default_backend": hasDefaultBackend,
		"annotations":         filterInterestingAnnotations(ing.Annotations),
		"rule_count":          len(ing.Spec.Rules),
		"labels":              copyStringMap(ing.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", IngressType, scope.Name, ing.Namespace, ing.Name),
		Type:       IngressType,
		Name:       ing.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) networkPolicyResource(scope *ContextScope, np *networkingv1.NetworkPolicy) compliancekit.Resource {
	types := make([]string, 0, len(np.Spec.PolicyTypes))
	for _, t := range np.Spec.PolicyTypes {
		types = append(types, string(t))
	}
	attrs := map[string]any{
		"namespace":               np.Namespace,
		"pod_selector":            copyStringMap(np.Spec.PodSelector.MatchLabels),
		"matches_all_pods":        len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0,
		"policy_types":            types,
		"ingress_rule_count":      len(np.Spec.Ingress),
		"egress_rule_count":       len(np.Spec.Egress),
		"has_allow_all_ingress":   hasAllowAllIngress(np.Spec.Ingress),
		"has_allow_all_egress":    hasAllowAllEgress(np.Spec.Egress),
		"has_from_all_namespaces": hasFromAllNamespaces(np.Spec.Ingress),
		"labels":                  copyStringMap(np.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", NetworkPolicyType, scope.Name, np.Namespace, np.Name),
		Type:       NetworkPolicyType,
		Name:       np.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

// ---- Flatteners ----

func flattenServicePorts(ports []corev1.ServicePort) []any {
	out := make([]any, 0, len(ports))
	for _, p := range ports {
		out = append(out, map[string]any{
			"port":      int(p.Port),
			"protocol":  string(p.Protocol),
			"node_port": int(p.NodePort),
			"name":      p.Name,
		})
	}
	return out
}

// interestingIngressAnnotations is the set of annotations the
// dangerous-annotation check reads. Other annotations are excluded
// from the attribute map to keep findings deterministic across
// scans.
var interestingIngressAnnotations = []string{
	"nginx.ingress.kubernetes.io/configuration-snippet",
	"nginx.ingress.kubernetes.io/server-snippet",
	"nginx.ingress.kubernetes.io/auth-snippet",
	"nginx.ingress.kubernetes.io/modsecurity-snippet",
	"nginx.ingress.kubernetes.io/lua-resty-waf",
}

func filterInterestingAnnotations(annos map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range interestingIngressAnnotations {
		if v, ok := annos[k]; ok {
			out[k] = v
		}
	}
	return out
}

// hasAllowAllIngress reports whether any ingress rule has an empty
// `from` block, which the K8s NetworkPolicy spec defines as "allow
// from any source." The K8s spec is subtle here: an empty `from`
// slice in a rule means "allow from anywhere"; a rule with no
// `from`/`to` at all in the YAML serializes as an empty slice.
func hasAllowAllIngress(rules []networkingv1.NetworkPolicyIngressRule) bool {
	for _, r := range rules {
		if len(r.From) == 0 {
			return true
		}
	}
	return false
}

func hasAllowAllEgress(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, r := range rules {
		if len(r.To) == 0 {
			return true
		}
	}
	return false
}

// hasFromAllNamespaces detects a peer with empty namespaceSelector
// (matches every namespace). That is "from all namespaces" — common
// misconfiguration intended as "from any pod in this namespace."
func hasFromAllNamespaces(rules []networkingv1.NetworkPolicyIngressRule) bool {
	for _, r := range rules {
		for _, peer := range r.From {
			if peer.NamespaceSelector != nil {
				if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
					return true
				}
			}
		}
	}
	return false
}
