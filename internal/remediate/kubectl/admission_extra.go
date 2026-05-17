package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.21 phase 6 — kubectl strategies for the 8 admission + policy-
// engine + operator checks.

var admissionExtraEntries = map[string]psExtraEntry{
	"k8s-admission-webhook-timeout-bounded": {
		patch:    `kubectl patch validatingwebhookconfiguration <NAME> --type=json -p='[{"op":"replace","path":"/webhooks/0/timeoutSeconds","value":5}]'`,
		manifest: "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata:\n  name: <name>\nwebhooks:\n  - name: validator.example.com\n    timeoutSeconds: 5     # ≤ 10; lower (1-3s) for hot-path validators\n    failurePolicy: Fail\n    sideEffects: None\n    admissionReviewVersions: [v1]\n    clientConfig:\n      service:\n        name: validator\n        namespace: my-validator\n        port: 443",
		risk:     remediate.RiskReview,
		notes:    "Lowering timeoutSeconds can cause legitimate webhook calls to error under load. Verify the webhook's p99 latency at the current production rate before tightening below 10s.",
	},
	"k8s-mutating-webhook-side-effects-none": {
		patch:    `kubectl patch mutatingwebhookconfiguration <NAME> --type=json -p='[{"op":"replace","path":"/webhooks/0/sideEffects","value":"None"}]'`,
		manifest: "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingWebhookConfiguration\nmetadata:\n  name: <name>\nwebhooks:\n  - name: mutator.example.com\n    sideEffects: None              # or NoneOnDryRun if webhook code differs on dry-run\n    timeoutSeconds: 5\n    failurePolicy: Fail",
		risk:     remediate.RiskReview,
		notes:    "If the webhook actually has side effects (audit log writes, metric emission), refactor the webhook code to eliminate the out-of-band write — don't lie about sideEffects.",
	},
	"k8s-admission-webhook-excludes-kube-system": {
		patch:    `kubectl patch validatingwebhookconfiguration <NAME> --type=json -p='[{"op":"add","path":"/webhooks/0/namespaceSelector","value":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["kube-system","kube-public","kube-node-lease"]}]}}]'`,
		manifest: "webhooks:\n  - name: validator.example.com\n    namespaceSelector:\n      matchExpressions:\n        - key: kubernetes.io/metadata.name\n          operator: NotIn\n          values:\n            - kube-system\n            - kube-public\n            - kube-node-lease",
		risk:     remediate.RiskReview,
		notes:    "Use `kubernetes.io/metadata.name` (the auto-added namespace label per k8s 1.21+) rather than `name` — the latter requires the operator to manually label every namespace.",
	},
	"k8s-cluster-gatekeeper-installed": {
		patch:    "helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts\nhelm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace",
		manifest: "# Gatekeeper Constraint example (after install):\napiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sRequiredLabels\nmetadata:\n  name: require-app-label\nspec:\n  enforcementAction: deny     # not dryrun in production\n  match:\n    kinds:\n      - apiGroups: [\"\"]\n        kinds: [Pod]\n  parameters:\n    labels: [app, env]",
		risk:     remediate.RiskReview,
	},
	"k8s-cluster-kyverno-installed": {
		patch:    "helm repo add kyverno https://kyverno.github.io/kyverno/\nhelm install kyverno kyverno/kyverno -n kyverno --create-namespace",
		manifest: "# Kyverno ClusterPolicy example (after install):\napiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: require-app-label\nspec:\n  validationFailureAction: enforce   # not audit in production\n  background: true\n  rules:\n    - name: require-labels\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n      validate:\n        message: \"pods must have app and env labels\"\n        pattern:\n          metadata:\n            labels:\n              app: \"?*\"\n              env: \"?*\"",
		risk:     remediate.RiskReview,
	},
	"k8s-cluster-policy-engine-enforce-mode": {
		patch:    "# Switch Gatekeeper Constraint to deny:\nkubectl patch k8srequiredlabels <CONSTRAINT> --type=merge -p '{\"spec\":{\"enforcementAction\":\"deny\"}}'\n# Switch Kyverno ClusterPolicy to enforce:\nkubectl patch clusterpolicy <POLICY> --type=merge -p '{\"spec\":{\"validationFailureAction\":\"enforce\"}}'",
		manifest: "# Gatekeeper:\nspec:\n  enforcementAction: deny   # not dryrun\n---\n# Kyverno:\nspec:\n  validationFailureAction: enforce   # not audit",
		risk:     remediate.RiskReview,
		notes:    "Switching from audit to enforce mid-stream will start blocking previously-violating resources. Stage with namespaceSelector exceptions for the namespaces that need a remediation window.",
	},
	"k8s-cluster-olm-installed": {
		patch:    "# Install OLM (Operator Lifecycle Manager):\ncurl -sL https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.28.0/install.sh | bash -s v0.28.0",
		manifest: "# After OLM install, subscribe to an operator via Subscription:\napiVersion: operators.coreos.com/v1alpha1\nkind: Subscription\nmetadata:\n  name: my-operator\n  namespace: operators\nspec:\n  channel: stable\n  name: my-operator\n  source: operatorhubio-catalog\n  sourceNamespace: olm\n  installPlanApproval: Manual    # not Automatic for production",
		risk:     remediate.RiskReview,
	},
	"k8s-operator-subscription-manual-approval": {
		patch:    `kubectl patch subscription <NAME> -n <NS> --type=merge -p '{"spec":{"installPlanApproval":"Manual"}}'`,
		manifest: "apiVersion: operators.coreos.com/v1alpha1\nkind: Subscription\nmetadata:\n  name: <name>\n  namespace: <ns>\nspec:\n  channel: stable\n  installPlanApproval: Manual   # operator review window per upgrade",
		risk:     remediate.RiskSafe,
		notes:    "Pair with a monitoring alert on `kubectl get installplan -n <ns>` showing pending plans, so review windows don't sit unattended.",
	},
}

func init() {
	for id, e := range admissionExtraEntries {
		id := id
		e := e
		register("kubectl-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			body := "# === kubectl patch ===\n" + e.patch + "\n\n# === Manifest (GitOps) ===\n" + e.manifest + "\n"
			return remediate.Snippet{
				Risk: e.risk, Idempotent: true, Content: body,
				Notes: e.notes,
			}, nil
		})
	}
}

// v0.21 phase 10 — kubectl backfill for the 9 legacy admission /
// namespace / policy / resourcequota check IDs. See
// backfill_helper.go for the renderer.
func init() {
	registerBackfillIDs(
		"k8s-mutating-webhook-side-effects",
		"k8s-validating-webhook-failure-policy",
		"k8s-webhook-namespace-selector",
		"k8s-namespace-default-workload",
		"k8s-namespace-stuck-terminating",
		"k8s-policy-engine-present",
		"k8s-resourcequota-compute-limit",
		"k8s-resourcequota-object-counts",
		"k8s-resourcequota-pod-limit",
	)
}
