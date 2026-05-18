package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkService(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":                   "default",
		"type":                        "ClusterIP",
		"external_ips":                []string{},
		"load_balancer_source_ranges": []string{},
		"ports":                       []any{},
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.svc.prod.default." + name,
		Type:       k8scol.ServiceType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkIngress(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":           "default",
		"ingress_class":       "nginx",
		"has_tls":             true,
		"has_default_backend": false,
		"annotations":         map[string]string{},
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.ing.prod.default." + name,
		Type:       k8scol.IngressType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkNetworkPolicy(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":               "default",
		"matches_all_pods":        false,
		"policy_types":            []string{"Ingress"},
		"ingress_rule_count":      0,
		"egress_rule_count":       0,
		"has_allow_all_ingress":   false,
		"has_allow_all_egress":    false,
		"has_from_all_namespaces": false,
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.np.prod.default." + name,
		Type:       k8scol.NetworkPolicyType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func TestServiceLBPublic(t *testing.T) {
	g := newPodGraph(
		mkService("clusterip", nil),
		mkService("lb-locked", map[string]any{"type": "LoadBalancer", "load_balancer_source_ranges": []string{"10.0.0.0/8"}}),
		mkService("lb-open", map[string]any{"type": "LoadBalancer"}),
	)
	got := runCheck(t, ServiceLBPublic, g)
	if _, ok := got["clusterip"]; ok {
		t.Errorf("clusterip should be skipped")
	}
	if got["lb-locked"] != compliancekit.StatusPass || got["lb-open"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestServiceLBPlainHTTP(t *testing.T) {
	g := newPodGraph(
		mkService("https", map[string]any{
			"type":  "LoadBalancer",
			"ports": []any{map[string]any{"port": 443}},
		}),
		mkService("dual", map[string]any{
			"type":  "LoadBalancer",
			"ports": []any{map[string]any{"port": 80}, map[string]any{"port": 443}},
		}),
		mkService("plain", map[string]any{
			"type":  "LoadBalancer",
			"ports": []any{map[string]any{"port": 80}},
		}),
	)
	got := runCheck(t, ServiceLBPlainHTTP, g)
	if got["https"] != compliancekit.StatusPass || got["dual"] != compliancekit.StatusPass {
		t.Errorf("https/dual: %v / %v", got["https"], got["dual"])
	}
	if got["plain"] != compliancekit.StatusFail {
		t.Errorf("plain: %v", got["plain"])
	}
}

func TestServiceExternalIPs(t *testing.T) {
	g := newPodGraph(
		mkService("clean", nil),
		mkService("set", map[string]any{"external_ips": []string{"1.2.3.4"}}),
	)
	got := runCheck(t, ServiceExternalIPs, g)
	if got["clean"] != compliancekit.StatusPass || got["set"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestServiceNodePort(t *testing.T) {
	g := newPodGraph(
		mkService("clusterip", nil),
		mkService("nodeport", map[string]any{"type": "NodePort"}),
	)
	got := runCheck(t, ServiceNodePort, g)
	if got["clusterip"] != compliancekit.StatusPass || got["nodeport"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestServicePublicNoNP(t *testing.T) {
	g := newPodGraph(
		mkService("lb-covered", map[string]any{"type": "LoadBalancer", "namespace": "app"}),
		mkNetworkPolicy("any", map[string]any{"namespace": "app"}),
		mkService("lb-bare", map[string]any{"type": "LoadBalancer", "namespace": "noapp"}),
	)
	got := runCheck(t, ServicePublicNoNP, g)
	if got["lb-covered"] != compliancekit.StatusPass || got["lb-bare"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestIngressTLS(t *testing.T) {
	g := newPodGraph(
		mkIngress("good", nil),
		mkIngress("bare", map[string]any{"has_tls": false}),
	)
	got := runCheck(t, IngressTLS, g)
	if got["good"] != compliancekit.StatusPass || got["bare"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestIngressDefaultBackend(t *testing.T) {
	g := newPodGraph(
		mkIngress("good", nil),
		mkIngress("catchall", map[string]any{"has_default_backend": true}),
	)
	got := runCheck(t, IngressDefaultBackend, g)
	if got["good"] != compliancekit.StatusPass || got["catchall"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestIngressClass(t *testing.T) {
	g := newPodGraph(
		mkIngress("good", nil),
		mkIngress("unset", map[string]any{"ingress_class": ""}),
	)
	got := runCheck(t, IngressClass, g)
	if got["good"] != compliancekit.StatusPass || got["unset"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestIngressAnnotations(t *testing.T) {
	g := newPodGraph(
		mkIngress("good", nil),
		mkIngress("snippet", map[string]any{"annotations": map[string]string{"nginx.ingress.kubernetes.io/configuration-snippet": "..."}}),
	)
	got := runCheck(t, IngressAnnotations, g)
	if got["good"] != compliancekit.StatusPass || got["snippet"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestNPDefaultDenyIngress(t *testing.T) {
	g := newPodGraph(
		// app namespace has a default-deny ingress policy
		mkPod("p1", map[string]any{"namespace": "app"}),
		mkNetworkPolicy("default-deny", map[string]any{
			"namespace":          "app",
			"matches_all_pods":   true,
			"policy_types":       []string{"Ingress"},
			"ingress_rule_count": 0,
		}),
		// noapp has a pod but no NP
		mkPod("p2", map[string]any{"namespace": "noapp"}),
	)
	findings, _ := NPDefaultDenyIngress(t.Context(), g)
	byNs := map[string]compliancekit.Status{}
	for _, f := range findings {
		byNs[f.Resource.Name] = f.Status
	}
	if byNs["app"] != compliancekit.StatusPass {
		t.Errorf("app: %v", byNs["app"])
	}
	if byNs["noapp"] != compliancekit.StatusFail {
		t.Errorf("noapp: %v", byNs["noapp"])
	}
}

func TestNPAllowAllIngress(t *testing.T) {
	g := newPodGraph(
		mkNetworkPolicy("scoped", nil),
		mkNetworkPolicy("open", map[string]any{"has_allow_all_ingress": true}),
	)
	got := runCheck(t, NPAllowAllIngress, g)
	if got["scoped"] != compliancekit.StatusPass || got["open"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestNPAllowAllEgress(t *testing.T) {
	g := newPodGraph(
		mkNetworkPolicy("scoped", nil),
		mkNetworkPolicy("open", map[string]any{"has_allow_all_egress": true}),
	)
	got := runCheck(t, NPAllowAllEgress, g)
	if got["scoped"] != compliancekit.StatusPass || got["open"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestNPFromAllNamespaces(t *testing.T) {
	g := newPodGraph(
		mkNetworkPolicy("scoped", nil),
		mkNetworkPolicy("any-ns", map[string]any{"has_from_all_namespaces": true}),
	)
	got := runCheck(t, NPFromAllNamespaces, g)
	if got["scoped"] != compliancekit.StatusPass || got["any-ns"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestNPEmptySelector(t *testing.T) {
	g := newPodGraph(
		mkNetworkPolicy("scoped", nil),
		mkNetworkPolicy("default-deny", map[string]any{
			"matches_all_pods":   true,
			"ingress_rule_count": 0,
			"egress_rule_count":  0,
		}),
		mkNetworkPolicy("all-pods-with-rules", map[string]any{
			"matches_all_pods":   true,
			"ingress_rule_count": 2,
		}),
	)
	got := runCheck(t, NPEmptySelector, g)
	if got["scoped"] != compliancekit.StatusPass || got["default-deny"] != compliancekit.StatusPass {
		t.Errorf("pass cases: %v", got)
	}
	if got["all-pods-with-rules"] != compliancekit.StatusFail {
		t.Errorf("all-pods-with-rules: %v", got["all-pods-with-rules"])
	}
}
