package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ----- Namespace default workload -------------------------------

var CheckNSDefaultWorkload = core.Check{
	ID:           "k8s-namespace-default-workload",
	Title:        "Workloads should not run in the default namespace",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.PodType,
	Description: "The `default` namespace exists as the no-op landing " +
		"zone for new clusters. Workloads scheduled there inherit the " +
		"namespace's `default` ServiceAccount (which has whatever " +
		"bindings exist on it cluster-wide), share quota and policy " +
		"with every other lazy deployment, and complicate audit. Real " +
		"workloads belong in named namespaces.",
	Remediation: "Create per-app namespaces and move workloads into " +
		"them. Apply PSA labels, NetworkPolicies, ResourceQuotas, and " +
		"LimitRanges to each.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"4.1", "6.7"},
	},
	Tags:    []string{"k8s", "namespace", "default"},
	Scanner: "cluster.NSDefaultWorkload",
}

func NSDefaultWorkload(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		ns, _ := p.Attributes["namespace"].(string)
		f := core.Finding{
			CheckID:  CheckNSDefaultWorkload.ID,
			Severity: CheckNSDefaultWorkload.Severity,
			Resource: p.Ref(),
			Tags:     CheckNSDefaultWorkload.Tags,
		}
		if ns == "default" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: scheduled in default namespace", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: namespace=%s", podDesc(p), ns)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Namespace ResourceQuota missing --------------------------

var CheckNSResourceQuota = core.Check{
	ID:           "k8s-namespace-resourcequota-missing",
	Title:        "Namespaces should have at least one ResourceQuota",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.NamespaceType,
	Description: "A namespace without a ResourceQuota has no cap on how " +
		"much CPU, memory, pods, or storage it can consume. A buggy " +
		"controller, a fork-bomb, or an OOM-storm in one namespace can " +
		"starve the whole cluster. Quotas are the K8s primitive for " +
		"namespace-level capacity guardrails.",
	Remediation: "Create a `ResourceQuota` per namespace with hard " +
		"caps on `pods`, `limits.cpu`, `limits.memory`, and " +
		"`count/secrets`/`count/configmaps` at minimum.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "namespace", "quota"},
	Scanner: "cluster.NSResourceQuota",
}

func NSResourceQuota(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	rqByNs := map[string]int{}
	for _, rq := range g.ByType(k8scol.ResourceQuotaType) {
		ns, _ := rq.Attributes["namespace"].(string)
		rqByNs[ns]++
	}
	findings := []core.Finding{}
	for _, ns := range g.ByType(k8scol.NamespaceType) {
		if isSys, _ := ns.Attributes["is_system"].(bool); isSys {
			continue
		}
		f := core.Finding{
			CheckID:  CheckNSResourceQuota.ID,
			Severity: CheckNSResourceQuota.Severity,
			Resource: ns.Ref(),
			Tags:     CheckNSResourceQuota.Tags,
		}
		if rqByNs[ns.Name] > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: %d ResourceQuota(s)", ns.Name, rqByNs[ns.Name])
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no ResourceQuota", ns.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Namespace LimitRange missing ------------------------------

var CheckNSLimitRange = core.Check{
	ID:           "k8s-namespace-limitrange-missing",
	Title:        "Namespaces should have at least one LimitRange",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.NamespaceType,
	Description: "A LimitRange supplies default CPU/memory requests + " +
		"limits to pods that don't declare them. Without one, the Pod " +
		"Security checks for resource limits will keep failing for " +
		"every workload an operator forgets to annotate.",
	Remediation: "Apply a LimitRange to each namespace with sensible " +
		"container defaults (e.g. 100m/128Mi requests, 1/1Gi limits).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "namespace", "quota"},
	Scanner: "cluster.NSLimitRange",
}

func NSLimitRange(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	lrByNs := map[string]int{}
	for _, lr := range g.ByType(k8scol.LimitRangeType) {
		ns, _ := lr.Attributes["namespace"].(string)
		if has, _ := lr.Attributes["has_container_defaults"].(bool); has {
			lrByNs[ns]++
		}
	}
	findings := []core.Finding{}
	for _, ns := range g.ByType(k8scol.NamespaceType) {
		if isSys, _ := ns.Attributes["is_system"].(bool); isSys {
			continue
		}
		f := core.Finding{
			CheckID:  CheckNSLimitRange.ID,
			Severity: CheckNSLimitRange.Severity,
			Resource: ns.Ref(),
			Tags:     CheckNSLimitRange.Tags,
		}
		if lrByNs[ns.Name] > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: LimitRange with container defaults", ns.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no LimitRange with container defaults", ns.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Namespace PSA label ---------------------------------------

var CheckNSPSALabel = core.Check{
	ID:           "k8s-namespace-psa-label",
	Title:        "Namespaces should set pod-security.kubernetes.io enforce label",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.NamespaceType,
	Description: "Pod Security Admission (PSA, GA in K8s 1.25) uses " +
		"namespace labels to enforce the baseline/restricted profiles. " +
		"Without an `enforce` label, the namespace runs the cluster " +
		"default — usually `privileged`, meaning no Pod Security gate " +
		"is in place. Set `enforce: restricted` on workload namespaces.",
	Remediation: "`kubectl label namespace <ns> " +
		"pod-security.kubernetes.io/enforce=restricted`. Stage with " +
		"`audit` or `warn` levels first if workloads might violate.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.9", "A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "namespace", "psa"},
	Scanner: "cluster.NSPSALabel",
}

func NSPSALabel(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ns := range g.ByType(k8scol.NamespaceType) {
		if isSys, _ := ns.Attributes["is_system"].(bool); isSys {
			continue
		}
		enforce, _ := ns.Attributes["psa_enforce"].(string)
		f := core.Finding{
			CheckID:  CheckNSPSALabel.ID,
			Severity: CheckNSPSALabel.Severity,
			Resource: ns.Ref(),
			Tags:     CheckNSPSALabel.Tags,
		}
		switch enforce {
		case "baseline", "restricted":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: PSA enforce=%s", ns.Name, enforce)
		case "privileged":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: PSA enforce=privileged (no Pod Security gate)", ns.Name)
		case "":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: no PSA enforce label", ns.Name)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: unknown PSA level %q", ns.Name, enforce)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Namespace stuck terminating -------------------------------

var CheckNSStuck = core.Check{
	ID:           "k8s-namespace-stuck-terminating",
	Title:        "Namespaces should not stay in Terminating phase",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.NamespaceType,
	Description: "A namespace that stays in `Terminating` indicates a " +
		"finalizer-stuck deletion — usually a CRD whose controller has " +
		"been removed without cleaning up its custom resources. Until " +
		"resolved, the namespace cannot be recreated and its resources " +
		"are in limbo.",
	Remediation: "`kubectl get namespace <name> -o json` reveals the " +
		"blocking finalizer. Either restore the controller, manually " +
		"clean its CRs, or (as a last resort) force-remove the " +
		"finalizer.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "namespace", "hygiene"},
	Scanner: "cluster.NSStuck",
}

func NSStuck(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ns := range g.ByType(k8scol.NamespaceType) {
		phase, _ := ns.Attributes["phase"].(string)
		f := core.Finding{
			CheckID:  CheckNSStuck.ID,
			Severity: CheckNSStuck.Severity,
			Resource: ns.Ref(),
			Tags:     CheckNSStuck.Tags,
		}
		if phase == "Terminating" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("namespace %q: stuck in Terminating", ns.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("namespace %q: phase=%s", ns.Name, phase)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Policy engine presence ------------------------------------

var CheckPolicyEnginePresence = core.Check{
	ID:           "k8s-policy-engine-present",
	Title:        "Cluster should have a policy engine installed",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "cluster",
	ResourceType: k8scol.ClusterType,
	Description: "Pod Security Admission covers the pod surface. For " +
		"everything else (image-from-registry-allowlist, label " +
		"requirements, RBAC restrictions, custom resource validation), " +
		"a dedicated policy engine — Kyverno, OPA Gatekeeper, or " +
		"jspolicy — is the modern primitive. Detection looks for the " +
		"engine's ValidatingWebhookConfigurations.",
	Remediation: "Install Kyverno (`helm install kyverno kyverno/kyverno`) " +
		"or OPA Gatekeeper. Apply org policies as Kyverno " +
		"ClusterPolicies or Gatekeeper ConstraintTemplates.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.9", "A.8.32"},
		"cis-v8":   {"4.1", "6.8"},
	},
	Tags:    []string{"k8s", "cluster", "policy"},
	Scanner: "cluster.PolicyEnginePresence",
}

// Known policy-engine webhook names. The engines all install
// ValidatingWebhookConfigurations whose names are stable.
var policyEngineWebhooks = []string{
	"kyverno", "gatekeeper", "open-policy-agent",
	"jspolicy", "validate.kyverno.svc",
}

func PolicyEnginePresence(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	found := []string{}
	for _, w := range g.ByType(k8scol.ValidatingWebhookConfigType) {
		for _, name := range policyEngineWebhooks {
			if strings.Contains(w.Name, name) {
				found = append(found, w.Name)
				break
			}
		}
	}
	findings := []core.Finding{}
	for _, cluster := range g.ByType(k8scol.ClusterType) {
		f := core.Finding{
			CheckID:  CheckPolicyEnginePresence.ID,
			Severity: CheckPolicyEnginePresence.Severity,
			Resource: cluster.Ref(),
			Tags:     CheckPolicyEnginePresence.Tags,
		}
		if len(found) > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("cluster %q: policy engine(s): %s", cluster.Name, strings.Join(found, ", "))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("cluster %q: no known policy engine detected", cluster.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Validating webhook FailurePolicy -------------------------

var CheckVWebhookFailurePolicy = core.Check{
	ID:           "k8s-validating-webhook-failure-policy",
	Title:        "Validating webhooks should set failurePolicy=Fail",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.ValidatingWebhookConfigType,
	Description: "`failurePolicy: Ignore` means a webhook outage silently " +
		"bypasses policy. That is appropriate only for advisory checks; " +
		"any security-critical webhook should fail closed (`Fail`) so " +
		"an outage halts admission rather than letting unchecked " +
		"resources through.",
	Remediation: "Set `failurePolicy: Fail` on security-relevant " +
		"webhooks. Pair with a `namespaceSelector` that exempts " +
		"kube-system so a webhook outage cannot brick the control " +
		"plane.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC7.2"},
		"iso27001": {"A.8.16", "A.8.32"},
		"cis-v8":   {"4.1", "8.11"},
	},
	Tags:    []string{"k8s", "admission", "webhook"},
	Scanner: "cluster.VWebhookFailurePolicy",
}

func VWebhookFailurePolicy(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, w := range g.ByType(k8scol.ValidatingWebhookConfigType) {
		f := core.Finding{
			CheckID:  CheckVWebhookFailurePolicy.ID,
			Severity: CheckVWebhookFailurePolicy.Severity,
			Resource: w.Ref(),
			Tags:     CheckVWebhookFailurePolicy.Tags,
		}
		ignore, _ := w.Attributes["has_ignore_policy"].(bool)
		if ignore {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("validatingwebhook %q: some webhook has failurePolicy=Ignore", w.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("validatingwebhook %q: all webhooks failurePolicy=Fail", w.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Mutating webhook side effects ----------------------------

var CheckMWebhookSideEffects = core.Check{
	ID:           "k8s-mutating-webhook-side-effects",
	Title:        "Mutating webhooks should declare sideEffects: None or NoneOnDryRun",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.MutatingWebhookConfigType,
	Description: "`sideEffects: Some` or unset means the webhook may " +
		"call out to external systems during admission, which makes " +
		"`kubectl --dry-run=server` unreliable and can stall " +
		"admission under load. Declare side-effect semantics " +
		"explicitly.",
	Remediation: "Set `sideEffects: None` if the webhook is purely " +
		"local, or `NoneOnDryRun` if it skips side effects on dry-run " +
		"requests.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "admission", "webhook"},
	Scanner: "cluster.MWebhookSideEffects",
}

func MWebhookSideEffects(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, w := range g.ByType(k8scol.MutatingWebhookConfigType) {
		side, _ := w.Attributes["has_side_effects"].(bool)
		f := core.Finding{
			CheckID:  CheckMWebhookSideEffects.ID,
			Severity: CheckMWebhookSideEffects.Severity,
			Resource: w.Ref(),
			Tags:     CheckMWebhookSideEffects.Tags,
		}
		if side {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("mutatingwebhook %q: some webhook declares external side effects", w.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("mutatingwebhook %q: sideEffects=None across webhooks", w.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Webhook namespaceSelector --------------------------------

var CheckWebhookNamespaceSelector = core.Check{
	ID:           "k8s-webhook-namespace-selector",
	Title:        "Cluster-wide webhooks should exempt kube-system via namespaceSelector",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.MutatingWebhookConfigType,
	Description: "A webhook with no `namespaceSelector` matches every " +
		"namespace including kube-system. If the webhook backing pod " +
		"goes down, the control plane components in kube-system cannot " +
		"create their own helper resources, and the cluster can lock " +
		"itself out of recovery. Exempt kube-system explicitly.",
	Remediation: "Add `namespaceSelector: {matchExpressions: [{key: " +
		"kubernetes.io/metadata.name, operator: NotIn, values: " +
		"[kube-system, kube-public]}]}`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "admission", "webhook", "control-plane"},
	Scanner: "cluster.WebhookNamespaceSelector",
}

func WebhookNamespaceSelector(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	// Iterate both validating + mutating; for each, check the
	// per-webhook has_ns_selector flag — if any webhook lacks it,
	// fail the whole configuration.
	for _, t := range []string{k8scol.ValidatingWebhookConfigType, k8scol.MutatingWebhookConfigType} {
		for _, w := range g.ByType(t) {
			webhooks, _ := w.Attributes["webhooks"].([]any)
			missing := []string{}
			for _, hi := range webhooks {
				h, ok := hi.(map[string]any)
				if !ok {
					continue
				}
				name, _ := h["name"].(string)
				if hasSel, _ := h["has_ns_selector"].(bool); !hasSel {
					missing = append(missing, name)
				}
			}
			f := core.Finding{
				CheckID:  CheckWebhookNamespaceSelector.ID,
				Severity: CheckWebhookNamespaceSelector.Severity,
				Resource: w.Ref(),
				Tags:     CheckWebhookNamespaceSelector.Tags,
			}
			if len(missing) == 0 {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("webhook %q: all webhooks have namespaceSelector", w.Name)
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("webhook %q: webhooks without namespaceSelector: %s", w.Name, strings.Join(missing, ", "))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ----- helpers + init --------------------------------------------

func init() {
	core.Register(CheckNSDefaultWorkload, NSDefaultWorkload)
	core.Register(CheckNSResourceQuota, NSResourceQuota)
	core.Register(CheckNSLimitRange, NSLimitRange)
	core.Register(CheckNSPSALabel, NSPSALabel)
	core.Register(CheckNSStuck, NSStuck)
	core.Register(CheckPolicyEnginePresence, PolicyEnginePresence)
	core.Register(CheckVWebhookFailurePolicy, VWebhookFailurePolicy)
	core.Register(CheckMWebhookSideEffects, MWebhookSideEffects)
	core.Register(CheckWebhookNamespaceSelector, WebhookNamespaceSelector)
	// v0.22 phase 4 — ResourceQuota + LimitRange registrations moved
	// to cluster_quotas.go.
}

func rqAttrCheck(g *core.ResourceGraph, check core.Check, attr, passMsg, failMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, rq := range g.ByType(k8scol.ResourceQuotaType) {
		ok, _ := rq.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: rq.Ref(),
			Tags:     check.Tags,
		}
		if ok {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("resourcequota %q: %s", workloadDesc(rq), passMsg)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("resourcequota %q: %s", workloadDesc(rq), failMsg)
		}
		findings = append(findings, f)
	}
	return findings
}

func missingResourceList(cpu, mem bool) string {
	missing := []string{}
	if !cpu {
		missing = append(missing, "cpu")
	}
	if !mem {
		missing = append(missing, "memory")
	}
	return strings.Join(missing, "+")
}
