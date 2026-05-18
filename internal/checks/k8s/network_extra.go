package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 4 — network depth. 10 new checks complementing the v0.11
// network.go (which owns NetworkPolicy default-deny, Ingress TLS,
// Service external IPs / NodePort). Lands in network_extra.go to keep
// network.go below the v0.22 600-LoC invariant.

// ----- 1. ingress configuration-snippet (RCE class) ----------------

var CheckIngressConfigurationSnippet = compliancekit.Check{
	ID:           "k8s-ingress-no-configuration-snippet",
	Title:        "Ingress objects must not use nginx configuration-snippet (RCE — CVE-2021-25742)",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "The nginx.ingress.kubernetes.io/configuration-snippet " +
		"annotation injects raw nginx config into the controller. CVE-2021-25742 " +
		"escalated this to full ingress-controller compromise via Lua evaluation. " +
		"Patched ingress-nginx releases disable the annotation by default + " +
		"require a controller flag to re-enable, but the manifest annotation " +
		"is still a strong signal of misconfiguration.",
	Remediation: "Remove the annotation. Express the same intent via " +
		"ingress-nginx-supported fields (rewrite-target, ssl-redirect, " +
		"server-alias) or move the customization into a sidecar / " +
		"separate nginx Deployment.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.7", "A.8.20"},
		"cis-v8":   {"4.7", "16.6"},
	},
	Tags:    []string{"k8s", "network", "ingress", "cve"},
	Scanner: "network.IngressConfigurationSnippet",
}

func IngressConfigurationSnippet(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ingressAnnotationCheck(g, CheckIngressConfigurationSnippet,
		"nginx.ingress.kubernetes.io/configuration-snippet"), nil
}

// ----- 2. ingress server-snippet (sibling RCE annotation) ----------

var CheckIngressServerSnippet = compliancekit.Check{
	ID:           "k8s-ingress-no-server-snippet",
	Title:        "Ingress objects must not use nginx server-snippet (CVE-2021-25742 sibling)",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "Same risk class as configuration-snippet: server-snippet " +
		"injects nginx server-block config. Patched ingress-nginx releases " +
		"require a controller flag to enable; manifest annotation is a " +
		"strong signal of misconfiguration.",
	Remediation: "Remove the annotation; express via supported fields.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.7", "A.8.20"},
		"cis-v8":   {"4.7", "16.6"},
	},
	Tags:    []string{"k8s", "network", "ingress", "cve"},
	Scanner: "network.IngressServerSnippet",
}

func IngressServerSnippet(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ingressAnnotationCheck(g, CheckIngressServerSnippet,
		"nginx.ingress.kubernetes.io/server-snippet"), nil
}

// ----- 3. ingress auth-snippet (CVE class) -------------------------

var CheckIngressAuthSnippet = compliancekit.Check{
	ID:           "k8s-ingress-no-auth-snippet",
	Title:        "Ingress objects must not use nginx auth-snippet annotation",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "auth-snippet runs arbitrary nginx config inside the auth " +
		"subrequest path — same class of escape as configuration-snippet " +
		"but scoped to the auth flow. Disabled by default in patched " +
		"controllers.",
	Remediation: "Use auth-url / auth-signin annotations with a side-car " +
		"auth service (oauth2-proxy, authelia) instead.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.7"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "network", "ingress", "cve"},
	Scanner: "network.IngressAuthSnippet",
}

func IngressAuthSnippet(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return ingressAnnotationCheck(g, CheckIngressAuthSnippet,
		"nginx.ingress.kubernetes.io/auth-snippet"), nil
}

// ----- 4. service zero-CIDR source ranges --------------------------

var CheckServiceZeroCIDRSourceRanges = compliancekit.Check{
	ID:           "k8s-service-no-zero-cidr-source-range",
	Title:        "Service loadBalancerSourceRanges must not contain 0.0.0.0/0",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "Setting loadBalancerSourceRanges to 0.0.0.0/0 defeats the " +
		"field's purpose — it's identical to leaving the field unset but " +
		"misleadingly claims source-IP restriction in audit. Auditors flag " +
		"explicit zero-CIDR as worse than no restriction (false-sense-of-" +
		"security antipattern).",
	Remediation: "Either remove loadBalancerSourceRanges entirely (so the " +
		"field's absence is honest) or replace 0.0.0.0/0 with a CIDR list " +
		"of legitimate ingress sources.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.6", "12.5"},
	},
	Tags:    []string{"k8s", "network", "loadbalancer"},
	Scanner: "network.ServiceZeroCIDRSourceRange",
}

func ServiceZeroCIDRSourceRange(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		f := compliancekit.Finding{
			CheckID: CheckServiceZeroCIDRSourceRanges.ID, Severity: CheckServiceZeroCIDRSourceRanges.Severity,
			Resource: s.Ref(), Tags: CheckServiceZeroCIDRSourceRanges.Tags,
		}
		sType, _ := s.Attributes["type"].(string)
		if sType != "LoadBalancer" {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("service %q: type=%s; loadBalancerSourceRanges not applicable", svcDesc(s), sType)
			findings = append(findings, f)
			continue
		}
		ranges, _ := s.Attributes["load_balancer_source_ranges"].([]string)
		hasZero := false
		for _, r := range ranges {
			if strings.TrimSpace(r) == "0.0.0.0/0" {
				hasZero = true
				break
			}
		}
		switch {
		case len(ranges) == 0:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("service %q: LoadBalancer with no source ranges (open to internet)", svcDesc(s))
		case hasZero:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("service %q: loadBalancerSourceRanges contains 0.0.0.0/0 (defeats the field)", svcDesc(s))
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("service %q: source ranges restricted: %s", svcDesc(s), strings.Join(ranges, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. networkpolicy egress to cloud metadata service -----------

var CheckNetworkPolicyMetadataEgress = compliancekit.Check{
	ID:           "k8s-networkpolicy-cloud-metadata-egress-blocked",
	Title:        "NetworkPolicies should block egress to 169.254.169.254 (cloud metadata)",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.NetworkPolicyType,
	Description: "Cloud metadata service (AWS IMDS, GCP metadata, Azure IMDS) " +
		"lives at 169.254.169.254. A pod that can reach it can request " +
		"node-role IAM credentials — instant pivot to cloud-account access. " +
		"NetworkPolicy egress with ipBlock except 169.254.169.254/32 is the " +
		"standard mitigation; IMDSv2 hop-limit-1 protection works on EC2 " +
		"but not on GCP / Azure. Manual-verify since the check requires " +
		"walking every NetworkPolicy ipBlock list per pod-selector.",
	Remediation: "Add an explicit egress block to every NetworkPolicy:\n  " +
		"- to:\n      - ipBlock:\n          cidr: 0.0.0.0/0\n          except:\n            - 169.254.169.254/32\n            - 169.254.170.2/32   # ECS task metadata\n            - fd00:ec2::254/128    # IMDSv6\n" +
		"On EKS, also enable IMDSv2-only on node groups via the launch template.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"6.6", "12.5"},
	},
	Tags:    []string{"k8s", "network", "metadata", "manual-verify"},
	Scanner: "network.NetworkPolicyMetadataEgress",
}

func NetworkPolicyMetadataEgress(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	// Manual-verify across the cluster — emits one Info finding per
	// cluster-context resource so the auditor knows to check + waive.
	findings := []compliancekit.Finding{}
	contexts := g.ByType(k8scol.ClusterType)
	if len(contexts) == 0 {
		return findings, nil
	}
	for _, ctx := range contexts {
		f := compliancekit.Finding{
			CheckID: CheckNetworkPolicyMetadataEgress.ID, Severity: CheckNetworkPolicyMetadataEgress.Severity,
			Resource: ctx.Ref(), Tags: CheckNetworkPolicyMetadataEgress.Tags,
			Status:  compliancekit.StatusError,
			Message: fmt.Sprintf("cluster %q: audit NetworkPolicy egress rules block 169.254.169.254/32 (cloud metadata IMDS) — `kubectl get networkpolicy -A -o yaml | grep -A 5 ipBlock`", ctx.Name),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. ingress dangerous lua-related annotations -----------------

var CheckIngressLuaPlugins = compliancekit.Check{
	ID:           "k8s-ingress-no-lua-plugins",
	Title:        "Ingress objects must not enable nginx Lua plugins via annotation",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "Lua plugin annotations (lua-resty-*, server-snippet with " +
		"Lua blocks) expose the Lua VM the ingress-nginx controller embeds. " +
		"Patched controllers disable Lua-eval annotations by default; their " +
		"presence in a manifest signals either an older controller " +
		"version OR an explicit re-enable.",
	Remediation: "Remove lua-* annotations. If you genuinely need Lua " +
		"middleware, deploy it as a sidecar nginx with a hand-curated " +
		"Lua bundle outside the ingress-nginx controller.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.7"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "network", "ingress", "lua"},
	Scanner: "network.IngressLuaPlugins",
}

func IngressLuaPlugins(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		f := compliancekit.Finding{
			CheckID: CheckIngressLuaPlugins.ID, Severity: CheckIngressLuaPlugins.Severity,
			Resource: ing.Ref(), Tags: CheckIngressLuaPlugins.Tags,
		}
		ann, _ := ing.Attributes["annotations"].(map[string]string)
		hit := []string{}
		for k := range ann {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "lua-") || strings.Contains(lk, "modsecurity-snippet") {
				hit = append(hit, k)
			}
		}
		if len(hit) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("ingress %q: no lua-* annotations", ingDesc(ing))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("ingress %q: lua/modsec snippet annotations: %s", ingDesc(ing), strings.Join(hit, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. service with publishNotReadyAddresses (manual-verify) ----

var CheckServicePublishNotReady = compliancekit.Check{
	ID:           "k8s-service-no-publish-not-ready-addresses",
	Title:        "Services should not enable publishNotReadyAddresses (bypasses readiness)",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "publishNotReadyAddresses: true makes the Service add " +
		"endpoints for pods that are not yet Ready. Legitimate for headless " +
		"discovery services (StatefulSet-style cluster bootstrap) but a " +
		"common foot-gun for general workloads — it routes traffic to pods " +
		"that have failed their readiness probe. Manual-verify since the " +
		"current collector doesn't surface the field.",
	Remediation: "Leave publishNotReadyAddresses unset (defaults to false). " +
		"For StatefulSet bootstrap use cases, ensure the StatefulSet is " +
		"the only consumer of the headless Service.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "network", "service", "manual-verify"},
	Scanner: "network.ServicePublishNotReady",
}

func ServicePublishNotReady(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		f := compliancekit.Finding{
			CheckID: CheckServicePublishNotReady.ID, Severity: CheckServicePublishNotReady.Severity,
			Resource: s.Ref(), Tags: CheckServicePublishNotReady.Tags,
			Status:  compliancekit.StatusError,
			Message: fmt.Sprintf("service %q: audit publishNotReadyAddresses — `kubectl get svc -n <ns> %s -o yaml | grep publishNotReady`", svcDesc(s), s.Name),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. service with too-broad selector (manual-verify) ----------

var CheckServiceSelectorBroad = compliancekit.Check{
	ID:           "k8s-service-selector-too-broad",
	Title:        "Services should not have empty / 1-label selectors (cross-workload exposure)",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "A Service with no selector or a single common label " +
		"(`app: nginx`) routes traffic to every pod in the namespace " +
		"matching that label — including pods the operator didn't intend " +
		"to expose. Namespace label-collisions are common. Audit " +
		"recommends multi-label selectors with version + instance " +
		"discriminators.",
	Remediation: "Add a discriminating label to both the Service selector " +
		"AND the target pods — typically `app.kubernetes.io/instance` " +
		"or a per-deployment unique label.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.22"},
		"cis-v8":   {"4.6"},
	},
	Tags:    []string{"k8s", "network", "service"},
	Scanner: "network.ServiceSelectorBroad",
}

func ServiceSelectorBroad(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		f := compliancekit.Finding{
			CheckID: CheckServiceSelectorBroad.ID, Severity: CheckServiceSelectorBroad.Severity,
			Resource: s.Ref(), Tags: CheckServiceSelectorBroad.Tags,
		}
		sType, _ := s.Attributes["type"].(string)
		if sType == "ExternalName" {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("service %q: type=ExternalName, no selector required", svcDesc(s))
			findings = append(findings, f)
			continue
		}
		sel, _ := s.Attributes["selector_labels"].(map[string]string)
		switch {
		case len(sel) == 0:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("service %q: empty selector (routes to every matching Endpoints object)", svcDesc(s))
		case len(sel) == 1:
			for k, v := range sel {
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("service %q: single-label selector %s=%s (collision risk)", svcDesc(s), k, v)
			}
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("service %q: %d-label selector", svcDesc(s), len(sel))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 9. ingress with no rules (default-backend-only catch-all) ---

var CheckIngressNoRules = compliancekit.Check{
	ID:           "k8s-ingress-no-rules-defined",
	Title:        "Ingress objects without rules expose every host via the controller's default-backend",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.IngressType,
	Description: "An Ingress with zero rules uses the controller's " +
		"default-backend for every request to every host. Typically a " +
		"manifest mistake (rules block deleted by accident) or a debug " +
		"primitive that escaped into production. The default-backend " +
		"usually serves a 404 page — but it's still a per-host wildcard " +
		"that interferes with other Ingress objects on the same controller.",
	Remediation: "Add explicit rules with host: + paths:. Use the controller's " +
		"defaultBackend field at the controller level for cluster-wide " +
		"fallback, not at the Ingress level.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.22"},
		"cis-v8":   {"4.6"},
	},
	Tags:    []string{"k8s", "network", "ingress"},
	Scanner: "network.IngressNoRules",
}

func IngressNoRules(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		f := compliancekit.Finding{
			CheckID: CheckIngressNoRules.ID, Severity: CheckIngressNoRules.Severity,
			Resource: ing.Ref(), Tags: CheckIngressNoRules.Tags,
		}
		count, _ := ing.Attributes["rule_count"].(int)
		hasDefault, _ := ing.Attributes["has_default_backend"].(bool)
		switch {
		case count > 0:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("ingress %q: %d rules", ingDesc(ing), count)
		case hasDefault:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("ingress %q: no rules + has defaultBackend (catches every host)", ingDesc(ing))
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("ingress %q: no rules defined", ingDesc(ing))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 10. service with both TLS and plaintext on same port (audit) -

var CheckServiceMixedTLSPlaintext = compliancekit.Check{
	ID:           "k8s-service-mixed-tls-plaintext-ports",
	Title:        "Services should not expose plaintext + TLS on overlapping ports",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "network",
	ResourceType: k8scol.ServiceType,
	Description: "A Service exposing both 80 (plaintext) and 443 (TLS) " +
		"with no `targetPort` discrimination forces the workload to " +
		"handle both — common pattern for legacy apps but discouraged " +
		"in zero-trust setups where TLS termination should happen at the " +
		"ingress / sidecar tier. Info-only — flags Services with both " +
		"port 80 + 443 for review.",
	Remediation: "Remove the :80 port from the Service. Terminate TLS at " +
		"the Ingress / sidecar tier (envoy, linkerd-proxy). For the " +
		"legitimate case (HTTP-redirect-to-HTTPS), serve the redirect " +
		"from the Ingress, not the backend Service.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.5.14", "A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"k8s", "network", "service", "tls", "manual-verify"},
	Scanner: "network.ServiceMixedTLSPlaintext",
}

func ServiceMixedTLSPlaintext(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, s := range g.ByType(k8scol.ServiceType) {
		f := compliancekit.Finding{
			CheckID: CheckServiceMixedTLSPlaintext.ID, Severity: CheckServiceMixedTLSPlaintext.Severity,
			Resource: s.Ref(), Tags: CheckServiceMixedTLSPlaintext.Tags,
		}
		ports, _ := s.Attributes["ports"].([]any)
		hasHTTP, hasHTTPS := false, false
		for _, pi := range ports {
			pm, ok := pi.(map[string]any)
			if !ok {
				continue
			}
			port, _ := pm["port"].(int64)
			if port == 80 {
				hasHTTP = true
			}
			if port == 443 {
				hasHTTPS = true
			}
		}
		switch {
		case hasHTTP && hasHTTPS:
			f.Status = compliancekit.StatusError
			f.Message = fmt.Sprintf("service %q: exposes both port 80 and 443 — audit whether plaintext is intentional", svcDesc(s))
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("service %q: no mixed-protocol port exposure", svcDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ---------- shared helpers --------------------------------------

func ingressAnnotationCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, annKey string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
	for _, ing := range g.ByType(k8scol.IngressType) {
		f := compliancekit.Finding{
			CheckID: check.ID, Severity: check.Severity,
			Resource: ing.Ref(), Tags: check.Tags,
		}
		ann, _ := ing.Attributes["annotations"].(map[string]string)
		if _, set := ann[annKey]; set {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("ingress %q: %s annotation set", ingDesc(ing), annKey)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("ingress %q: %s not set", ingDesc(ing), annKey)
		}
		findings = append(findings, f)
	}
	return findings
}

func svcDesc(s compliancekit.Resource) string {
	ns, _ := s.Attributes["namespace"].(string)
	if ns == "" {
		return s.Name
	}
	return ns + "/" + s.Name
}

func ingDesc(ing compliancekit.Resource) string {
	ns, _ := ing.Attributes["namespace"].(string)
	if ns == "" {
		return ing.Name
	}
	return ns + "/" + ing.Name
}

func init() {
	compliancekit.Register(CheckIngressConfigurationSnippet, IngressConfigurationSnippet)
	compliancekit.Register(CheckIngressServerSnippet, IngressServerSnippet)
	compliancekit.Register(CheckIngressAuthSnippet, IngressAuthSnippet)
	compliancekit.Register(CheckServiceZeroCIDRSourceRanges, ServiceZeroCIDRSourceRange)
	compliancekit.Register(CheckNetworkPolicyMetadataEgress, NetworkPolicyMetadataEgress)
	compliancekit.Register(CheckIngressLuaPlugins, IngressLuaPlugins)
	compliancekit.Register(CheckServicePublishNotReady, ServicePublishNotReady)
	compliancekit.Register(CheckServiceSelectorBroad, ServiceSelectorBroad)
	compliancekit.Register(CheckIngressNoRules, IngressNoRules)
	compliancekit.Register(CheckServiceMixedTLSPlaintext, ServiceMixedTLSPlaintext)
}
