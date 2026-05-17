package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 3 — Ingress checks split out of network.go.

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

func init() {
	core.Register(CheckIngressTLS, IngressTLS)
	core.Register(CheckIngressDefaultBackend, IngressDefaultBackend)
	core.Register(CheckIngressClass, IngressClass)
	core.Register(CheckIngressAnnotations, IngressAnnotations)
}
