package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 6 — admission webhook + policy-engine depth. 8 checks
// covering webhook-config dimensions cluster.go doesn't already
// validate, plus cluster-level manual-verify hooks for the policy-
// engine (Gatekeeper / Kyverno) + OLM ecosystem.

// ----- 1. webhook timeoutSeconds bounded ---------------------------

var CheckWebhookTimeoutBounded = core.Check{
	ID:           "k8s-admission-webhook-timeout-bounded",
	Title:        "Admission webhooks must set timeoutSeconds ≤ 10",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.ValidatingWebhookConfigType,
	Description: "The k8s default timeoutSeconds is 10s (since 1.14). " +
		"Webhooks that override to a higher value can stall the apiserver " +
		"under load — a slow webhook becomes a denial-of-service against " +
		"every CREATE/UPDATE in the cluster. CIS recommends ≤10s; SIG-auth " +
		"recommends much lower (1-3s) for hot-path validators.",
	Remediation: "In your ValidatingWebhookConfiguration / " +
		"MutatingWebhookConfiguration, set `timeoutSeconds: 5` (or lower " +
		"for hot-path validators). Cache expensive lookups inside the " +
		"webhook implementation so the apiserver call returns fast.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "admission", "webhook"},
	Scanner: "admission.WebhookTimeoutBounded",
}

func WebhookTimeoutBounded(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, t := range []string{k8scol.ValidatingWebhookConfigType, k8scol.MutatingWebhookConfigType} {
		for _, w := range g.ByType(t) {
			webhooks, _ := w.Attributes["webhooks"].([]any)
			bad := []string{}
			for _, wi := range webhooks {
				wm, ok := wi.(map[string]any)
				if !ok {
					continue
				}
				timeout, _ := wm["timeout_seconds"].(int32)
				if timeout > 10 {
					name, _ := wm["name"].(string)
					bad = append(bad, fmt.Sprintf("%s(timeout=%ds)", name, timeout))
				}
			}
			f := core.Finding{
				CheckID: CheckWebhookTimeoutBounded.ID, Severity: CheckWebhookTimeoutBounded.Severity,
				Resource: w.Ref(), Tags: CheckWebhookTimeoutBounded.Tags,
			}
			if len(bad) == 0 {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("webhook config %q: all webhooks ≤10s", w.Name)
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("webhook config %q: %s", w.Name, strings.Join(bad, ", "))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ----- 2. mutating webhook side effects -------------------------

var CheckMutatingWebhookSideEffectsNone = core.Check{
	ID:           "k8s-mutating-webhook-side-effects-none",
	Title:        "MutatingWebhooks should declare sideEffects=None (or NoneOnDryRun)",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.MutatingWebhookConfigType,
	Description: "sideEffects tells the apiserver whether the webhook " +
		"changes state outside the in-request resource (e.g. writes to " +
		"external systems). `Some` blocks dry-run support; `Unknown` is " +
		"deprecated. CIS + SIG-api-machinery require None or NoneOnDryRun " +
		"so dry-run requests can probe the cluster without triggering " +
		"side-effect-ful webhook code.",
	Remediation: "In the MutatingWebhookConfiguration, set " +
		"`sideEffects: None` (or `NoneOnDryRun` if the webhook genuinely " +
		"runs different code under dry-run). Refactor the webhook to " +
		"eliminate out-of-band writes triggered by the apiserver call.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "admission", "webhook"},
	Scanner: "admission.MutatingWebhookSideEffects",
}

func MutatingWebhookSideEffectsNone(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, w := range g.ByType(k8scol.MutatingWebhookConfigType) {
		webhooks, _ := w.Attributes["webhooks"].([]any)
		bad := []string{}
		for _, wi := range webhooks {
			wm, ok := wi.(map[string]any)
			if !ok {
				continue
			}
			se, _ := wm["side_effects"].(string)
			if se != "None" && se != "NoneOnDryRun" {
				name, _ := wm["name"].(string)
				bad = append(bad, fmt.Sprintf("%s(sideEffects=%s)", name, se))
			}
		}
		f := core.Finding{
			CheckID: CheckMutatingWebhookSideEffectsNone.ID, Severity: CheckMutatingWebhookSideEffectsNone.Severity,
			Resource: w.Ref(), Tags: CheckMutatingWebhookSideEffectsNone.Tags,
		}
		if len(bad) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("mutating webhook %q: all sideEffects None / NoneOnDryRun", w.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("mutating webhook %q: %s", w.Name, strings.Join(bad, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. webhook scoped (no kube-system bypass) -------------------

var CheckWebhookExcludesKubeSystem = core.Check{
	ID:           "k8s-admission-webhook-excludes-kube-system",
	Title:        "Admission webhooks should exclude kube-system via namespaceSelector",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "admission",
	ResourceType: k8scol.ValidatingWebhookConfigType,
	Description: "A webhook that intercepts kube-system can break the " +
		"control plane (apiserver can't talk to itself, kubelet can't " +
		"register). CIS recommends excluding kube-system via " +
		"namespaceSelector. Info-only if the webhook is a control-plane " +
		"webhook (cert-manager etc.) — but most validators should leave " +
		"system namespaces alone.",
	Remediation: "Add to every webhook entry:\n  namespaceSelector:\n    " +
		"matchExpressions:\n      - key: kubernetes.io/metadata.name\n        " +
		"operator: NotIn\n        values: [kube-system, kube-public, kube-node-lease]",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "admission", "webhook"},
	Scanner: "admission.WebhookExcludesKubeSystem",
}

func WebhookExcludesKubeSystem(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, t := range []string{k8scol.ValidatingWebhookConfigType, k8scol.MutatingWebhookConfigType} {
		for _, w := range g.ByType(t) {
			webhooks, _ := w.Attributes["webhooks"].([]any)
			bad := []string{}
			for _, wi := range webhooks {
				wm, ok := wi.(map[string]any)
				if !ok {
					continue
				}
				has, _ := wm["has_ns_selector"].(bool)
				if !has {
					name, _ := wm["name"].(string)
					bad = append(bad, name)
				}
			}
			f := core.Finding{
				CheckID: CheckWebhookExcludesKubeSystem.ID, Severity: CheckWebhookExcludesKubeSystem.Severity,
				Resource: w.Ref(), Tags: CheckWebhookExcludesKubeSystem.Tags,
			}
			if len(bad) == 0 {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("webhook config %q: all webhooks scope by namespace", w.Name)
			} else {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("webhook config %q: webhooks without namespaceSelector: %s", w.Name, strings.Join(bad, ", "))
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// ----- 4. policy engine — Gatekeeper installed (manual-verify) ----

var CheckGatekeeperInstalled = core.Check{
	ID:           "k8s-cluster-gatekeeper-installed",
	Title:        "OPA Gatekeeper should be installed for policy enforcement",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "policy",
	ResourceType: k8scol.ClusterType,
	Description: "Gatekeeper is the OPA-based admission policy engine. " +
		"Provides ConstraintTemplate (the policy) + Constraint (the " +
		"binding to resources) + audit Status. Either Gatekeeper OR " +
		"Kyverno (k8s-cluster-kyverno-installed) satisfies the policy-" +
		"engine requirement — most clusters pick one.",
	Remediation: "Install via Helm:\n  helm repo add gatekeeper " +
		"https://open-policy-agent.github.io/gatekeeper/charts\n  helm " +
		"install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system " +
		"--create-namespace",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "policy", "gatekeeper", "manual-verify"},
	Scanner: "admission.GatekeeperInstalled",
}

func GatekeeperInstalled(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckGatekeeperInstalled,
		"check for Gatekeeper: `kubectl get crd | grep gatekeeper.sh` should list constrainttemplates.templates.gatekeeper.sh + constrainttemplates.constraints.gatekeeper.sh")
}

// ----- 5. policy engine — Kyverno installed (manual-verify) ------

var CheckKyvernoInstalled = core.Check{
	ID:           "k8s-cluster-kyverno-installed",
	Title:        "Kyverno should be installed for policy enforcement",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "policy",
	ResourceType: k8scol.ClusterType,
	Description: "Kyverno is the Kubernetes-native admission policy engine. " +
		"Express policies as Kubernetes resources (ClusterPolicy / " +
		"Policy) with validate / mutate / generate / verifyImages rules. " +
		"Either Kyverno OR Gatekeeper (k8s-cluster-gatekeeper-installed) " +
		"satisfies the policy-engine requirement.",
	Remediation: "Install via Helm:\n  helm repo add kyverno " +
		"https://kyverno.github.io/kyverno/\n  helm install kyverno " +
		"kyverno/kyverno -n kyverno --create-namespace",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "policy", "kyverno", "manual-verify"},
	Scanner: "admission.KyvernoInstalled",
}

func KyvernoInstalled(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckKyvernoInstalled,
		"check for Kyverno: `kubectl get crd | grep kyverno.io` should list clusterpolicies.kyverno.io + policies.kyverno.io")
}

// ----- 6. policy enforcement mode (manual-verify) ------------------

var CheckPolicyEnforceMode = core.Check{
	ID:           "k8s-cluster-policy-engine-enforce-mode",
	Title:        "Policy-engine policies should be in enforce mode (not audit-only) in production",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "policy",
	ResourceType: k8scol.ClusterType,
	Description: "Gatekeeper Constraints + Kyverno ClusterPolicies both " +
		"support audit-only mode (`enforcementAction: dryrun` / " +
		"`validationFailureAction: audit`). Audit mode logs violations " +
		"but doesn't block them — useful for staged rollout, dangerous " +
		"if left on permanently. Production posture should be enforce " +
		"with named-namespace exceptions for migration windows.",
	Remediation: "For Gatekeeper Constraints:\n  enforcementAction: deny\n" +
		"For Kyverno ClusterPolicies:\n  validationFailureAction: enforce",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "policy", "manual-verify"},
	Scanner: "admission.PolicyEnforceMode",
}

func PolicyEnforceMode(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckPolicyEnforceMode,
		"`kubectl get constraints.constraints.gatekeeper.sh -A -o jsonpath='{.items[*].spec.enforcementAction}'` should not be `dryrun`; for Kyverno `kubectl get clusterpolicy -o jsonpath='{.items[*].spec.validationFailureAction}'` should be `enforce`")
}

// ----- 7. OLM installed (manual-verify) ---------------------------

var CheckOLMInstalled = core.Check{
	ID:           "k8s-cluster-olm-installed",
	Title:        "Operator Lifecycle Manager (OLM) should be installed for operator hygiene",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "operator",
	ResourceType: k8scol.ClusterType,
	Description: "OLM provides versioned operator install + upgrade " +
		"channels + per-operator Subscription with auto-approve " +
		"gating. Without OLM, operators ship raw manifests + " +
		"upgrades become manual kubectl apply rounds. Required only " +
		"on clusters running Kubernetes operators (not all clusters " +
		"do); info-level since some clusters legitimately don't run any.",
	Remediation: "Install via operatorhub.io:\n  curl -sL " +
		"https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.28.0/install.sh " +
		"| bash -s v0.28.0",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"k8s", "operator", "olm", "manual-verify"},
	Scanner: "operator.OLMInstalled",
}

func OLMInstalled(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckOLMInstalled,
		"check for OLM: `kubectl get crd subscriptions.operators.coreos.com clusterserviceversions.operators.coreos.com` should both exist if OLM is installed")
}

// ----- 8. operator subscription approval mode (manual-verify) -----

var CheckOperatorSubscriptionApproval = core.Check{
	ID:           "k8s-operator-subscription-manual-approval",
	Title:        "OLM Subscriptions should use Manual approval (not Automatic) for production",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "operator",
	ResourceType: k8scol.ClusterType,
	Description: "Subscription `installPlanApproval: Automatic` auto-" +
		"installs every operator upgrade that lands in the subscribed " +
		"channel — including major versions with breaking changes. " +
		"Production posture is Manual approval with a per-upgrade " +
		"review window. Info-only since some staging clusters " +
		"legitimately want Automatic.",
	Remediation: "Edit each Subscription:\n  spec:\n    installPlanApproval: " +
		"Manual\nApprove pending InstallPlans via `kubectl get installplan -n " +
		"<ns>` + `kubectl patch installplan <name> -n <ns> --type=merge -p " +
		"'{\"spec\":{\"approved\":true}}'`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"k8s", "operator", "olm", "manual-verify"},
	Scanner: "operator.SubscriptionApproval",
}

func OperatorSubscriptionApproval(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckOperatorSubscriptionApproval,
		"`kubectl get subscriptions.operators.coreos.com -A -o jsonpath='{.items[*].spec.installPlanApproval}'` should be Manual for production subscriptions")
}

func init() {
	core.Register(CheckWebhookTimeoutBounded, WebhookTimeoutBounded)
	core.Register(CheckMutatingWebhookSideEffectsNone, MutatingWebhookSideEffectsNone)
	core.Register(CheckWebhookExcludesKubeSystem, WebhookExcludesKubeSystem)
	core.Register(CheckGatekeeperInstalled, GatekeeperInstalled)
	core.Register(CheckKyvernoInstalled, KyvernoInstalled)
	core.Register(CheckPolicyEnforceMode, PolicyEnforceMode)
	core.Register(CheckOLMInstalled, OLMInstalled)
	core.Register(CheckOperatorSubscriptionApproval, OperatorSubscriptionApproval)
}
