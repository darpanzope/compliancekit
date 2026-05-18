package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 3 — NetworkPolicy checks split out of network.go.

// ----- NetworkPolicy default-deny ingress -----------------------

var CheckNPDefaultDenyIngress = compliancekit.Check{
	ID:           "k8s-networkpolicy-default-deny-ingress",
	Title:        "Each namespace should have a default-deny ingress NetworkPolicy",
	Severity:     compliancekit.SeverityHigh,
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
func NPDefaultDenyIngress(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return namespaceNPCoverageCheck(g, CheckNPDefaultDenyIngress, "Ingress"), nil
}

// ----- NetworkPolicy default-deny egress ------------------------

var CheckNPDefaultDenyEgress = compliancekit.Check{
	ID:           "k8s-networkpolicy-default-deny-egress",
	Title:        "Each namespace should have a default-deny egress NetworkPolicy",
	Severity:     compliancekit.SeverityMedium,
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

func NPDefaultDenyEgress(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return namespaceNPCoverageCheck(g, CheckNPDefaultDenyEgress, "Egress"), nil
}

// ----- NetworkPolicy namespace coverage --------------------------

var CheckNPNamespaceHasAny = compliancekit.Check{
	ID:           "k8s-networkpolicy-namespace-coverage",
	Title:        "Workload namespaces should have at least one NetworkPolicy",
	Severity:     compliancekit.SeverityMedium,
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

func NPNamespaceHasAny(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	npsByNs := map[string]int{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		ns, _ := np.Attributes["namespace"].(string)
		npsByNs[ns]++
	}
	findings := []compliancekit.Finding{}
	for _, ns := range knownNamespaces(g) {
		if isSystemNamespace(ns) {
			continue
		}
		f := compliancekit.Finding{
			CheckID:  CheckNPNamespaceHasAny.ID,
			Severity: CheckNPNamespaceHasAny.Severity,
			Resource: compliancekit.ResourceRef{ID: "k8s.namespace." + ns, Type: k8scol.NamespaceType, Name: ns},
			Tags:     CheckNPNamespaceHasAny.Tags,
		}
		if npsByNs[ns] > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("namespace %q: %d NetworkPolicy resource(s)", ns, npsByNs[ns])
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no NetworkPolicy resources", ns)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- NetworkPolicy allow-all ingress ---------------------------

var CheckNPAllowAllIngress = compliancekit.Check{
	ID:           "k8s-networkpolicy-allow-all-ingress",
	Title:        "NetworkPolicies should not have allow-all ingress rules",
	Severity:     compliancekit.SeverityMedium,
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

func NPAllowAllIngress(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return npAttributeCheck(g, CheckNPAllowAllIngress, "has_allow_all_ingress",
		"rule allows from any source",
		"no rule allows all ingress"), nil
}

// ----- NetworkPolicy allow-all egress ----------------------------

var CheckNPAllowAllEgress = compliancekit.Check{
	ID:           "k8s-networkpolicy-allow-all-egress",
	Title:        "NetworkPolicies should not have allow-all egress rules",
	Severity:     compliancekit.SeverityMedium,
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

func NPAllowAllEgress(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return npAttributeCheck(g, CheckNPAllowAllEgress, "has_allow_all_egress",
		"rule allows to any destination",
		"no rule allows all egress"), nil
}

// ----- NetworkPolicy from all namespaces -------------------------

var CheckNPFromAllNamespaces = compliancekit.Check{
	ID:           "k8s-networkpolicy-from-all-namespaces",
	Title:        "NetworkPolicies should not allow ingress from all namespaces",
	Severity:     compliancekit.SeverityMedium,
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

func NPFromAllNamespaces(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return npAttributeCheck(g, CheckNPFromAllNamespaces, "has_from_all_namespaces",
		"peer matches all namespaces",
		"no all-namespaces peer"), nil
}

// ----- NetworkPolicy empty selector ------------------------------

var CheckNPEmptySelector = compliancekit.Check{
	ID:           "k8s-networkpolicy-empty-selector",
	Title:        "NetworkPolicies with empty podSelector apply to every pod",
	Severity:     compliancekit.SeverityLow,
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

func NPEmptySelector(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, np := range g.ByType(k8scol.NetworkPolicyType) {
		matchesAll, _ := np.Attributes["matches_all_pods"].(bool)
		ingressCount, _ := np.Attributes["ingress_rule_count"].(int)
		egressCount, _ := np.Attributes["egress_rule_count"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckNPEmptySelector.ID,
			Severity: CheckNPEmptySelector.Severity,
			Resource: np.Ref(),
			Tags:     CheckNPEmptySelector.Tags,
		}
		// matchesAll plus zero rules == valid default-deny; pass.
		// matchesAll plus rules == suspicious all-pods allow.
		switch {
		case !matchesAll:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("networkpolicy %q: scoped via podSelector", networkDesc(np))
		case ingressCount == 0 && egressCount == 0:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("networkpolicy %q: default-deny pattern (matches all pods, no rules)", networkDesc(np))
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("networkpolicy %q: empty podSelector with %d/%d ingress/egress rules", networkDesc(np), ingressCount, egressCount)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckNPDefaultDenyIngress, NPDefaultDenyIngress)
	compliancekit.Register(CheckNPDefaultDenyEgress, NPDefaultDenyEgress)
	compliancekit.Register(CheckNPNamespaceHasAny, NPNamespaceHasAny)
	compliancekit.Register(CheckNPAllowAllIngress, NPAllowAllIngress)
	compliancekit.Register(CheckNPAllowAllEgress, NPAllowAllEgress)
	compliancekit.Register(CheckNPFromAllNamespaces, NPFromAllNamespaces)
	compliancekit.Register(CheckNPEmptySelector, NPEmptySelector)
}
