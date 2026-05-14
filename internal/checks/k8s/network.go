package k8s

import (
	"context"
	"fmt"
	"strings"

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

// ----- Ingress TLS --------------------------------------------

var CheckIngressTLS = core.Check{
	ID:           "k8s-ingress-tls-missing",
	Title:        "Ingresses should configure TLS",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "An Ingress without a `spec.tls` section terminates " +
		"plain HTTP at the ingress controller. Outside of behind-a-LB " +
		"setups where TLS terminates upstream, this exposes traffic " +
		"in cleartext.",
	Remediation: "Add a `spec.tls` entry referencing a Secret of type " +
		"kubernetes.io/tls. cert-manager + Let's Encrypt is the " +
		"standard automated path.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.20", "A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"k8s", "network", "ingress", "tls"},
	Scanner: "network.IngressTLS",
}

func IngressTLS(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		hasTLS, _ := ing.Attributes["has_tls"].(bool)
		f := ingressFinding(CheckIngressTLS, ing)
		if hasTLS {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ingress %q: TLS configured", networkDesc(ing))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ingress %q: no TLS section", networkDesc(ing))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Ingress default backend ----------------------------------

var CheckIngressDefaultBackend = core.Check{
	ID:           "k8s-ingress-default-backend",
	Title:        "Ingresses should not declare a default backend",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "A default backend catches every unmatched request and " +
		"sends it to the named service. That makes the ingress reachable " +
		"for arbitrary hostnames (path traversal, SSRF surface). Most " +
		"production setups prefer explicit host+path rules and let " +
		"unmatched traffic 404.",
	Remediation: "Remove `spec.defaultBackend` and add explicit `rules`. " +
		"If you genuinely need a catch-all, document the intent.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"12.5"},
	},
	Tags:    []string{"k8s", "network", "ingress"},
	Scanner: "network.IngressDefaultBackend",
}

func IngressDefaultBackend(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		def, _ := ing.Attributes["has_default_backend"].(bool)
		f := ingressFinding(CheckIngressDefaultBackend, ing)
		if def {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ingress %q: has default backend (catches every unmatched request)", networkDesc(ing))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ingress %q: no default backend", networkDesc(ing))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Ingress class set ----------------------------------------

var CheckIngressClass = core.Check{
	ID:           "k8s-ingress-class-set",
	Title:        "Ingresses should set ingressClassName explicitly",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "Without `ingressClassName`, every ingress controller " +
		"in the cluster may claim and serve the Ingress — leading to " +
		"unpredictable routing on multi-controller clusters. Setting " +
		"the class explicitly is unambiguous and the modern best practice.",
	Remediation: "Set `spec.ingressClassName: <name>` (e.g. nginx, " +
		"traefik, alb) on every Ingress. Remove the deprecated " +
		"kubernetes.io/ingress.class annotation.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "network", "ingress", "hygiene"},
	Scanner: "network.IngressClass",
}

func IngressClass(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		class, _ := ing.Attributes["ingress_class"].(string)
		f := ingressFinding(CheckIngressClass, ing)
		if class != "" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ingress %q: ingressClassName=%q", networkDesc(ing), class)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ingress %q: ingressClassName not set", networkDesc(ing))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Ingress dangerous annotations ----------------------------

var CheckIngressAnnotations = core.Check{
	ID:           "k8s-ingress-dangerous-annotations",
	Title:        "Ingresses should not use snippet annotations (RCE risk)",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "ingress-nginx allows arbitrary nginx configuration via " +
		"the `configuration-snippet`, `server-snippet`, " +
		"`auth-snippet`, and `modsecurity-snippet` annotations. CVEs " +
		"in this surface have repeatedly turned Ingress write access " +
		"into cluster-wide RCE — most recently CVE-2025-1974 " +
		"('IngressNightmare'). Disable the snippet annotations cluster-" +
		"wide (`--enable-snippets=false`) and audit any existing use.",
	Remediation: "Remove the snippet annotations and reconfigure via " +
		"ConfigMap settings or a dedicated module. Set " +
		"`allow-snippet-annotations: false` on the ingress controller " +
		"and `enable-snippets: false`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.8"},
		"iso27001": {"A.8.2", "A.8.9", "A.8.32"},
		"cis-v8":   {"12.5", "16.13"},
	},
	Tags:    []string{"k8s", "network", "ingress", "rce", "critical"},
	Scanner: "network.IngressAnnotations",
}

func IngressAnnotations(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		annos, _ := ing.Attributes["annotations"].(map[string]string)
		f := ingressFinding(CheckIngressAnnotations, ing)
		matched := []string{}
		for k := range annos {
			matched = append(matched, k)
		}
		if len(matched) > 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ingress %q: dangerous annotations: %s", networkDesc(ing), strings.Join(matched, ", "))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ingress %q: no snippet annotations", networkDesc(ing))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- NetworkPolicy default-deny ingress -----------------------

var CheckNPDefaultDenyIngress = core.Check{
	ID:           "k8s-networkpolicy-default-deny-ingress",
	Title:        "Each namespace should have a default-deny ingress NetworkPolicy",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NamespaceType,
	Description: "Without a default-deny ingress NetworkPolicy, every " +
		"pod in the namespace is reachable from every other pod in " +
		"the cluster. A compromise of one pod becomes a lateral-" +
		"movement primitive. The default-deny pattern is `podSelector: " +
		"{}` + `policyTypes: [Ingress]` and no ingress rules — that " +
		"baselines deny-all, and additive policies open specific flows.",
	Remediation: "Apply the default-deny manifest to every workload " +
		"namespace. Then add allow-list NetworkPolicies for the " +
		"specific flows each workload needs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.7"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy", "default-deny"},
	Scanner: "network.NPDefaultDenyIngress",
}

// Phase 4 ships the default-deny check against the set of namespaces
// referenced by Services/Pods/etc. Phase 6 will add the explicit
// k8s.namespace resource and re-target this against it.
func NPDefaultDenyIngress(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return namespaceNPCoverageCheck(g, CheckNPDefaultDenyIngress, "Ingress"), nil
}

// ----- NetworkPolicy default-deny egress ------------------------

var CheckNPDefaultDenyEgress = core.Check{
	ID:           "k8s-networkpolicy-default-deny-egress",
	Title:        "Each namespace should have a default-deny egress NetworkPolicy",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NamespaceType,
	Description: "Default-deny egress is the second half of namespace " +
		"isolation. Without it, a compromised workload can call out to " +
		"any internal service plus any external endpoint, exfiltrating " +
		"data or pivoting to the cloud control plane via the node's " +
		"IMDS. Pair with explicit allow rules to in-cluster DNS, " +
		"upstream APIs, and any external dependencies.",
	Remediation: "Apply a default-deny egress NetworkPolicy " +
		"(`podSelector: {}`, `policyTypes: [Egress]`, no egress " +
		"rules) plus allow-list rules to kube-dns and required " +
		"external endpoints.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.7"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy", "default-deny", "egress"},
	Scanner: "network.NPDefaultDenyEgress",
}

func NPDefaultDenyEgress(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return namespaceNPCoverageCheck(g, CheckNPDefaultDenyEgress, "Egress"), nil
}

// ----- NetworkPolicy namespace coverage --------------------------

var CheckNPNamespaceHasAny = core.Check{
	ID:           "k8s-networkpolicy-namespace-coverage",
	Title:        "Workload namespaces should have at least one NetworkPolicy",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NamespaceType,
	Description: "A namespace with no NetworkPolicy resources has a " +
		"flat allow-all network. The bar for posture compliance " +
		"frameworks (SOC 2, ISO 27001, NIST) is that *some* network " +
		"segmentation exists. Default-deny is preferred (see related " +
		"checks); even an allow-list policy is better than none.",
	Remediation: "Apply at least one NetworkPolicy. The default-deny " +
		"baseline is the safest starting point.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy"},
	Scanner: "network.NPNamespaceHasAny",
}

func NPNamespaceHasAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	npsByNs := map[string]int{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		ns, _ := np.Attributes["namespace"].(string)
		npsByNs[ns]++
	}
	findings := []core.Finding{}
	for _, ns := range knownNamespaces(g) {
		if isSystemNamespace(ns) {
			continue
		}
		f := core.Finding{
			CheckID:  CheckNPNamespaceHasAny.ID,
			Severity: CheckNPNamespaceHasAny.Severity,
			Resource: core.ResourceRef{ID: "k8s.namespace." + ns, Type: k8scol.NamespaceType, Name: ns},
			Tags:     CheckNPNamespaceHasAny.Tags,
		}
		if npsByNs[ns] > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: %d NetworkPolicy resource(s)", ns, npsByNs[ns])
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no NetworkPolicy resources", ns)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- NetworkPolicy allow-all ingress ---------------------------

var CheckNPAllowAllIngress = core.Check{
	ID:           "k8s-networkpolicy-allow-all-ingress",
	Title:        "NetworkPolicies should not have allow-all ingress rules",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NetworkPolicyType,
	Description: "A NetworkPolicy with an empty `from` block (or a rule " +
		"with no ingress fields beyond ports) allows traffic from " +
		"anywhere in the cluster. This is rarely the intent — usually " +
		"the operator meant 'from any pod in this namespace,' which " +
		"requires an empty `podSelector` peer.",
	Remediation: "Specify the source of allowed traffic explicitly: " +
		"`from: [{podSelector: {}}]` for same-namespace, " +
		"`from: [{namespaceSelector: {matchLabels: {...}}}]` for " +
		"cross-namespace, `from: [{ipBlock: {cidr: ...}}]` for external.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy"},
	Scanner: "network.NPAllowAllIngress",
}

func NPAllowAllIngress(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return npAttributeCheck(g, CheckNPAllowAllIngress, "has_allow_all_ingress",
		"rule allows from any source",
		"no rule allows all ingress"), nil
}

// ----- NetworkPolicy allow-all egress ----------------------------

var CheckNPAllowAllEgress = core.Check{
	ID:           "k8s-networkpolicy-allow-all-egress",
	Title:        "NetworkPolicies should not have allow-all egress rules",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NetworkPolicyType,
	Description: "An empty `to` block in an egress rule allows traffic " +
		"to anywhere — internal, external, the cloud control plane. " +
		"The legitimate use cases are narrow; the dangerous ones are " +
		"common.",
	Remediation: "List the allowed destinations explicitly: " +
		"`to: [{podSelector: {matchLabels: {...}}}]` for in-cluster, " +
		"`to: [{ipBlock: {cidr: ..., except: ['169.254.169.254/32']}}]` " +
		"for external (with the cloud IMDS excluded).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy", "egress"},
	Scanner: "network.NPAllowAllEgress",
}

func NPAllowAllEgress(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return npAttributeCheck(g, CheckNPAllowAllEgress, "has_allow_all_egress",
		"rule allows to any destination",
		"no rule allows all egress"), nil
}

// ----- NetworkPolicy from all namespaces -------------------------

var CheckNPFromAllNamespaces = core.Check{
	ID:           "k8s-networkpolicy-from-all-namespaces",
	Title:        "NetworkPolicies should not allow ingress from all namespaces",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NetworkPolicyType,
	Description: "An ingress peer with `namespaceSelector: {}` selects " +
		"every namespace in the cluster. The intent is usually to " +
		"allow traffic from a specific tier (e.g. all `monitoring` " +
		"namespaces) — instead it grants every workload from every " +
		"tenant. Always pair namespaceSelector with at least one " +
		"matchLabels rule.",
	Remediation: "Add labels to source namespaces and reference them: " +
		"`namespaceSelector: {matchLabels: {tier: monitoring}}`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "network", "policy"},
	Scanner: "network.NPFromAllNamespaces",
}

func NPFromAllNamespaces(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return npAttributeCheck(g, CheckNPFromAllNamespaces, "has_from_all_namespaces",
		"peer matches all namespaces",
		"no all-namespaces peer"), nil
}

// ----- NetworkPolicy empty selector ------------------------------

var CheckNPEmptySelector = core.Check{
	ID:           "k8s-networkpolicy-empty-selector",
	Title:        "NetworkPolicies with empty podSelector apply to every pod",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NetworkPolicyType,
	Description: "An empty `podSelector` matches every pod in the " +
		"namespace. That is the right choice for default-deny baselines " +
		"but the wrong choice for additive allow-list policies — every " +
		"such allow rule applies to every pod. Mostly informational; " +
		"verify intent.",
	Remediation: "If this is a default-deny policy, ignore (or rename " +
		"the policy `default-deny`). If it is an additive allow rule, " +
		"add a `matchLabels` clause to restrict scope.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "network", "policy", "informational"},
	Scanner: "network.NPEmptySelector",
}

func NPEmptySelector(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		matchesAll, _ := np.Attributes["matches_all_pods"].(bool)
		ingressCount, _ := np.Attributes["ingress_rule_count"].(int)
		egressCount, _ := np.Attributes["egress_rule_count"].(int)
		f := core.Finding{
			CheckID:  CheckNPEmptySelector.ID,
			Severity: CheckNPEmptySelector.Severity,
			Resource: np.Ref(),
			Tags:     CheckNPEmptySelector.Tags,
		}
		// matchesAll plus zero rules == valid default-deny; pass.
		// matchesAll plus rules == suspicious all-pods allow.
		switch {
		case !matchesAll:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("networkpolicy %q: scoped via podSelector", networkDesc(np))
		case ingressCount == 0 && egressCount == 0:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("networkpolicy %q: default-deny pattern (matches all pods, no rules)", networkDesc(np))
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("networkpolicy %q: empty podSelector with %d/%d ingress/egress rules", networkDesc(np), ingressCount, egressCount)
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
	core.Register(CheckIngressTLS, IngressTLS)
	core.Register(CheckIngressDefaultBackend, IngressDefaultBackend)
	core.Register(CheckIngressClass, IngressClass)
	core.Register(CheckIngressAnnotations, IngressAnnotations)
	core.Register(CheckNPDefaultDenyIngress, NPDefaultDenyIngress)
	core.Register(CheckNPDefaultDenyEgress, NPDefaultDenyEgress)
	core.Register(CheckNPNamespaceHasAny, NPNamespaceHasAny)
	core.Register(CheckNPAllowAllIngress, NPAllowAllIngress)
	core.Register(CheckNPAllowAllEgress, NPAllowAllEgress)
	core.Register(CheckNPFromAllNamespaces, NPFromAllNamespaces)
	core.Register(CheckNPEmptySelector, NPEmptySelector)
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
