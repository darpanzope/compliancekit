// Package helm implements remediate.Strategy renderers for the
// FormatHelm output. Helm-deployed K8s workloads can't be patched
// in the rendered manifests (the next `helm upgrade` overwrites
// them) — strategies here emit values.yaml overlays the operator
// merges into their existing release values.
//
// Chart values schemas vary, so the strategies emit a representative
// shape that maps cleanly onto common charts (bitnami/*, ingress-
// nginx, the kube-prometheus-stack family). Operators with a custom
// chart adjust the key path to match.
package helm

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatHelm} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatHelm {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("helm-pod-security",
		[]string{
			"k8s-pod-run-as-non-root",
			"k8s-pod-allow-privilege-escalation",
			"k8s-pod-readonly-root-fs",
			"k8s-pod-capabilities-drop-all",
			"k8s-pod-dangerous-capabilities",
			"k8s-pod-seccomp-profile",
			"k8s-pod-privileged",
		},
		renderPodSecurityOverlay)
	register("helm-resource-limits",
		[]string{
			"k8s-pod-resource-limits",
			"k8s-pod-resource-requests",
		},
		renderResourcesOverlay)
	register("helm-pdb",
		[]string{
			"k8s-deployment-pdb-missing",
			"k8s-statefulset-pdb-missing",
		},
		renderPDBOverlay)
	register("helm-replicas",
		[]string{"k8s-deployment-min-replicas"}, renderReplicasOverlay)
	register("helm-network-policy",
		[]string{
			"k8s-networkpolicy-default-deny-ingress",
			"k8s-networkpolicy-default-deny-egress",
		},
		renderNetworkPolicyOverlay)
	register("helm-service-account",
		[]string{"k8s-pod-automount-sa-token", "k8s-sa-default-automount"},
		renderServiceAccountOverlay)
}

func renderPodSecurityOverlay(_ core.Finding) (remediate.Snippet, error) {
	values := `# Merge into your existing values.yaml. Most charts surface these
# under .Values.podSecurityContext + .Values.securityContext —
# but key paths VARY by chart. Inspect the chart's templates/ to
# confirm.

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  privileged: false
  capabilities:
    drop:
      - ALL
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: values,
		Notes: "Apply via `helm upgrade $RELEASE $CHART -f values.yaml -f remediation.yaml`. If the chart wires these via a single .Values.security key (some bitnami charts do), nest under that instead.",
	}, nil
}

func renderResourcesOverlay(_ core.Finding) (remediate.Snippet, error) {
	values := `resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 1
    memory: 1Gi
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: values,
		Notes: "Right-size to actual usage (kubectl top pod, Prometheus). limits == requests gives QoS Guaranteed for latency-critical workloads.",
	}, nil
}

func renderPDBOverlay(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "REPLACE_RELEASE_NAME"
	}
	values := fmt.Sprintf(`# Many charts gate PDB creation on .Values.podDisruptionBudget.enabled.
podDisruptionBudget:
  enabled: true
  minAvailable: 1
  # maxUnavailable: 1    # alternative; pick one

# If the chart doesn't ship a PDB template, render one in your release's
# templates/ overlay or apply the standalone manifest:
#   kubectl apply -f - <<'EOF'
#   apiVersion: policy/v1
#   kind: PodDisruptionBudget
#   metadata: {name: %s-pdb}
#   spec: {minAvailable: 1, selector: {matchLabels: {app.kubernetes.io/name: %s}}}
#   EOF
`, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: values,
		Notes: "Verify your chart exposes podDisruptionBudget.* — bitnami/charts surface this; older charts don't.",
	}, nil
}

func renderReplicasOverlay(_ core.Finding) (remediate.Snippet, error) {
	values := `# Most charts respect .Values.replicaCount (or .Values.replicas).
replicaCount: 3

# For autoscaling, charts usually expose autoscaling.* — prefer
# HPA when the workload can scale horizontally.
autoscaling:
  enabled: false   # set to true and tune min/max if your workload supports HPA
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: values,
	}, nil
}

func renderNetworkPolicyOverlay(_ core.Finding) (remediate.Snippet, error) {
	values := `# Many charts ship NetworkPolicy templates gated on this flag.
networkPolicy:
  enabled: true
  # Default-deny stance — chart should generate allow-rules for
  # legitimate ingress (Service → pods) and egress (DNS, the
  # service's own dependencies).
  allowExternal: false
  egress: []         # explicit egress allows
  ingressNSPodLabels: {}
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: values,
		Notes: "Charts vary widely here. Inspect templates/networkpolicy.yaml in the chart — some emit a single NP, some emit one per workload. Without an audited allow-list, applying this can black-hole the release.",
	}, nil
}

func renderServiceAccountOverlay(_ core.Finding) (remediate.Snippet, error) {
	values := `serviceAccount:
  create: true
  automountServiceAccountToken: false
  # If the workload legitimately needs the kube-apiserver token
  # (operators, leader-election, in-cluster Helm), set this back
  # to true and grant minimum RBAC via a Role + RoleBinding.
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: values,
	}, nil
}
