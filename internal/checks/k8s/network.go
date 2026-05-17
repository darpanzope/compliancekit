package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ----- Service LoadBalancer public exposure ----------------------

var CheckServiceLBPublic = core.Check{
	ID:           "k8s-service-loadbalancer-source-ranges",
	Title:        "LoadBalancer Services should restrict source ranges",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "A Service with `type: LoadBalancer` and no " +
		"`loadBalancerSourceRanges` is reachable from the entire public " +
		"internet. For an admin endpoint (Argo CD, Prometheus, " +
		"Grafana, internal SaaS dashboards) this is often unintended. " +
		"Set source ranges to the operator's office / VPN CIDR.",
	Remediation: "Add `spec.loadBalancerSourceRanges: [<cidr1>, " +
		"<cidr2>]`. For workloads that genuinely should be public, " +
		"document the intent via an annotation or waiver.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.7"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5", "13.6"},
	},
	Tags:    []string{"k8s", "network", "loadbalancer", "exposure"},
	Scanner: "network.ServiceLBPublic",
}

func ServiceLBPublic(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		t, _ := s.Attributes["type"].(string)
		if t != "LoadBalancer" {
			continue
		}
		sr, _ := s.Attributes["load_balancer_source_ranges"].([]string)
		f := serviceFinding(CheckServiceLBPublic, s)
		if len(sr) > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("service %q: LB restricted to %d source range(s)", networkDesc(s), len(sr))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("service %q: LoadBalancer without source-range restriction", networkDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Service LoadBalancer plain HTTP ---------------------------

var CheckServiceLBPlainHTTP = core.Check{
	ID:           "k8s-service-loadbalancer-no-tls",
	Title:        "LoadBalancer Services should not expose plain HTTP only",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "A LoadBalancer service that only exposes port 80 ships " +
		"every request and response in cleartext. K8s does not handle " +
		"TLS termination at the Service level — operators typically " +
		"front the service with an Ingress or terminate TLS in-pod. " +
		"Expose 443 too (or 443-only) so traffic can be encrypted.",
	Remediation: "Add a 443/TCP port to the Service definition and " +
		"terminate TLS at the workload, or front the workload with " +
		"an Ingress carrying a TLS section.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20", "A.8.24"},
		"cis-v8":   {"3.10", "12.5"},
	},
	Tags:    []string{"k8s", "network", "loadbalancer", "tls"},
	Scanner: "network.ServiceLBPlainHTTP",
}

func ServiceLBPlainHTTP(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		t, _ := s.Attributes["type"].(string)
		if t != "LoadBalancer" {
			continue
		}
		ports, _ := s.Attributes["ports"].([]any)
		has80, has443 := portsHaveSpecific(ports, 80, 443)
		f := serviceFinding(CheckServiceLBPlainHTTP, s)
		switch {
		case has80 && !has443:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("service %q: LB exposes port 80 without 443", networkDesc(s))
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("service %q: LB ports OK", networkDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Service ExternalIPs --------------------------------------

var CheckServiceExternalIPs = core.Check{
	ID:           "k8s-service-external-ips",
	Title:        "Services should not set spec.externalIPs",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "`spec.externalIPs` lets an operator route arbitrary " +
		"node IPs to a Service. It bypasses both LoadBalancer and " +
		"Ingress paths and exists primarily for legacy bare-metal " +
		"deployments. There is a well-known privilege escalation via " +
		"externalIPs if a tenant can mutate Services (CVE-2020-8554).",
	Remediation: "Use `type: LoadBalancer` with a real LB, or `type: " +
		"NodePort`, or an Ingress. If externalIPs is genuinely needed, " +
		"deploy an admission policy restricting which IPs are allowed.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5", "13.6"},
	},
	Tags:    []string{"k8s", "network", "external-ips"},
	Scanner: "network.ServiceExternalIPs",
}

func ServiceExternalIPs(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		ips, _ := s.Attributes["external_ips"].([]string)
		f := serviceFinding(CheckServiceExternalIPs, s)
		if len(ips) > 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("service %q: externalIPs set: %v", networkDesc(s), ips)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("service %q: no externalIPs", networkDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Service NodePort exposure --------------------------------

var CheckServiceNodePort = core.Check{
	ID:           "k8s-service-nodeport",
	Title:        "Services should generally not use type: NodePort",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "`type: NodePort` opens a port on every node — every " +
		"node, even those not running the workload. Without a network " +
		"policy to filter traffic, the service is reachable from any " +
		"node-attached subnet. Most modern clusters should use " +
		"LoadBalancer or Ingress instead and let NodePort exist only " +
		"as the kube-proxy implementation detail under those.",
	Remediation: "Switch to LoadBalancer (real cloud LB) or Ingress " +
		"(routed via an in-cluster controller). Keep NodePort only " +
		"for tightly scoped infra (kube-apiserver via metallb, etc.).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5"},
	},
	Tags:    []string{"k8s", "network", "nodeport"},
	Scanner: "network.ServiceNodePort",
}

func ServiceNodePort(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		t, _ := s.Attributes["type"].(string)
		if t == "" {
			continue
		}
		f := serviceFinding(CheckServiceNodePort, s)
		if t == "NodePort" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("service %q: type=NodePort", networkDesc(s))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("service %q: type=%s", networkDesc(s), t)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Service public without network policy ---------------------

var CheckServicePublicNoNP = core.Check{
	ID:           "k8s-service-public-without-network-policy",
	Title:        "Public Services should run in a namespace with at least one NetworkPolicy",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "A namespace with a public-facing Service " +
		"(LoadBalancer/NodePort) and no NetworkPolicy has no egress " +
		"or ingress filtering — a compromise of the public-facing pod " +
		"can talk to anything cluster-internal. Defense in depth " +
		"requires at least one policy in the namespace, ideally a " +
		"default-deny baseline.",
	Remediation: "Apply a default-deny NetworkPolicy to the namespace " +
		"(`podSelector: {}`, policyTypes: [Ingress, Egress]), then " +
		"allow the specific flows the workload needs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.7"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy", "defense-in-depth"},
	Scanner: "network.ServicePublicNoNP",
}

func ServicePublicNoNP(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	npsByNs := map[string]int{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		ns, _ := np.Attributes["namespace"].(string)
		npsByNs[ns]++
	}
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		t, _ := s.Attributes["type"].(string)
		ns, _ := s.Attributes["namespace"].(string)
		if t != "LoadBalancer" && t != "NodePort" {
			continue
		}
		f := serviceFinding(CheckServicePublicNoNP, s)
		if npsByNs[ns] > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("service %q: namespace has %d NetworkPolicy resource(s)", networkDesc(s), npsByNs[ns])
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("service %q: %s exposed but namespace %q has no NetworkPolicy", networkDesc(s), t, ns)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers + init --------------------------------------------

func init() {
	core.Register(CheckServiceLBPublic, ServiceLBPublic)
	core.Register(CheckServiceLBPlainHTTP, ServiceLBPlainHTTP)
	core.Register(CheckServiceExternalIPs, ServiceExternalIPs)
	core.Register(CheckServiceNodePort, ServiceNodePort)
	core.Register(CheckServicePublicNoNP, ServicePublicNoNP)
	// v0.22 phase 3 — Ingress checks moved to network_ingress.go;
	// NetworkPolicy checks moved to network_policies.go.
}

// serviceFinding / ingressFinding wrap the common finding construction.
func serviceFinding(check core.Check, svc core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: svc.Ref(),
		Tags:     check.Tags,
	}
}

func ingressFinding(check core.Check, ing core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: ing.Ref(),
		Tags:     check.Tags,
	}
}

// networkDesc returns "ns/name" for namespaced resources.
func networkDesc(r core.Resource) string {
	ns, _ := r.Attributes["namespace"].(string)
	if ns == "" {
		return r.Name
	}
	return ns + "/" + r.Name
}

// portsHaveSpecific reports whether the service-ports slice contains
// the given ports. Used by ServiceLBPlainHTTP.
func portsHaveSpecific(ports []any, want ...int) (has0, has1 bool) {
	got := map[int]bool{}
	for _, pi := range ports {
		p, ok := pi.(map[string]any)
		if !ok {
			continue
		}
		port, _ := p["port"].(int)
		got[port] = true
	}
	if len(want) != 2 {
		return false, false
	}
	return got[want[0]], got[want[1]]
}

// namespaceNPCoverageCheck asserts that every workload-bearing
// namespace has at least one NetworkPolicy whose podSelector matches
// all pods AND whose policyTypes includes the named type AND whose
// rules are empty (= default-deny semantics).
func namespaceNPCoverageCheck(g *core.ResourceGraph, check core.Check, policyType string) []core.Finding {
	coveredByNs := map[string]bool{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		ns, _ := np.Attributes["namespace"].(string)
		matchesAll, _ := np.Attributes["matches_all_pods"].(bool)
		if !matchesAll {
			continue
		}
		types, _ := np.Attributes["policy_types"].([]string)
		typeApplies := false
		for _, t := range types {
			if t == policyType {
				typeApplies = true
				break
			}
		}
		if !typeApplies {
			continue
		}
		ingressCount, _ := np.Attributes["ingress_rule_count"].(int)
		egressCount, _ := np.Attributes["egress_rule_count"].(int)
		// Default-deny has zero rules of the matching direction. Allow
		// the opposite direction (the same policy can cover both).
		switch policyType {
		case "Ingress":
			if ingressCount == 0 {
				coveredByNs[ns] = true
			}
		case "Egress":
			if egressCount == 0 {
				coveredByNs[ns] = true
			}
		}
	}

	findings := []core.Finding{}
	for _, ns := range knownNamespaces(g) {
		if isSystemNamespace(ns) {
			continue
		}
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: core.ResourceRef{ID: "k8s.namespace." + ns, Type: k8scol.NamespaceType, Name: ns},
			Tags:     check.Tags,
		}
		if coveredByNs[ns] {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: default-deny %s NetworkPolicy in place", ns, policyType)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no default-deny %s NetworkPolicy", ns, policyType)
		}
		findings = append(findings, f)
	}
	return findings
}

// knownNamespaces returns the set of namespaces referenced by any
// namespaced resource in the graph. Until Phase 6 lands the explicit
// k8s.namespace resource type, this is the inferred set.
func knownNamespaces(g *core.ResourceGraph) []string {
	seen := map[string]struct{}{}
	for _, types := range [][]string{
		{k8scol.PodType, k8scol.DeploymentType, k8scol.StatefulSetType, k8scol.DaemonSetType,
			k8scol.JobType, k8scol.CronJobType, k8scol.ServiceType, k8scol.IngressType,
			k8scol.NetworkPolicyType, k8scol.SecretType, k8scol.ConfigMapType,
			k8scol.PersistentVolumeClaimType, k8scol.RoleType, k8scol.RoleBindingType,
			k8scol.ServiceAccountType, k8scol.PodDisruptionBudgetType,
			k8scol.ResourceQuotaType, k8scol.LimitRangeType},
	} {
		for _, t := range types {
			for _, r := range g.ByType(t) {
				if ns, ok := r.Attributes["namespace"].(string); ok && ns != "" {
					seen[ns] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	return out
}

// npAttributeCheck flags any NetworkPolicy whose named bool attribute
// is true.
func npAttributeCheck(g *core.ResourceGraph, check core.Check, attr, failMsg, passMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		flag, _ := np.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: np.Ref(),
			Tags:     check.Tags,
		}
		if flag {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("networkpolicy %q: %s", networkDesc(np), failMsg)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("networkpolicy %q: %s", networkDesc(np), passMsg)
		}
		findings = append(findings, f)
	}
	return findings
}
