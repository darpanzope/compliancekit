package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 4 — doctl strategies for the 10 DOKS-depth checks.
// Cluster + node-pool operations go through `doctl kubernetes`; add-on
// installations (cert-manager, metrics-server) are kubectl/helm-only
// and the strategies render those one-liners alongside the doctl
// kubeconfig fetch.

func init() {
	register("doctl-doks-version-supported",
		[]string{"k8s-doks-version-deprecated"}, renderDoctlDOKSVersion)
	register("doctl-doks-nodepool-taints",
		[]string{"k8s-doks-nodepool-no-taints"}, renderDoctlDOKSTaints)
	register("doctl-doks-nodepool-environment-tag",
		[]string{"k8s-doks-nodepool-no-environment-tag"}, renderDoctlDOKSEnvTag)
	register("doctl-doks-nodepool-size-supported",
		[]string{"k8s-doks-nodepool-size-retired"}, renderDoctlDOKSSize)
	register("doctl-doks-maintenance-quiet-hours",
		[]string{"k8s-doks-maintenance-window-loud-hours"}, renderDoctlDOKSMaintenance)
	register("doctl-doks-control-plane-logging",
		[]string{"k8s-doks-control-plane-logging-exported"}, renderDoctlDOKSLogging)
	register("doctl-doks-metrics-server",
		[]string{"k8s-doks-metrics-server-installed"}, renderDoctlDOKSMetricsServer)
	register("doctl-doks-cert-manager",
		[]string{"k8s-doks-cert-manager-installed"}, renderDoctlDOKSCertManager)
	register("doctl-doks-cluster-autoscaler",
		[]string{"k8s-doks-cluster-autoscaler-eligible"}, renderDoctlDOKSAutoscaler)
	register("doctl-doks-pod-security-standards",
		[]string{"k8s-doks-pod-security-standards-baseline"}, renderDoctlDOKSPSA)
}

func doctlDOKSCluster(f compliancekit.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "CLUSTER"
}

func renderDoctlDOKSVersion(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# 1. List supported versions.
doctl kubernetes options versions list

# 2. Upgrade in maintenance window (replace <newver> with the picked slug).
doctl kubernetes cluster upgrade %s --version <newver>`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster get %s --format Version", c),
		Notes:     "Stage in non-prod first. The upgrade is online with surge_upgrade on, but plan a maintenance window anyway.",
	}, nil
}

func renderDoctlDOKSTaints(f compliancekit.Finding) (remediate.Snippet, error) {
	pool := doctlDOKSCluster(f) // for node pool, Name is the pool
	body := fmt.Sprintf(`# Taint the node pool. Existing pods on the pool are NOT evicted; new
# pods without a matching toleration won't schedule onto it.
doctl kubernetes cluster node-pool update CLUSTER_ID %s \
  --taint "dedicated=%s:NoSchedule"`, pool, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl get nodes -l doks.digitalocean.com/node-pool=" + pool + " -o jsonpath='{.items[*].spec.taints}'",
		Notes:     "Set toleration on the workloads that should target this pool. Without tolerations, new pods avoid it.",
	}, nil
}

func renderDoctlDOKSEnvTag(f compliancekit.Finding) (remediate.Snippet, error) {
	pool := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# Tags on node pools are immutable after create on doctl; recreate
# the pool to add the tag, or use the TF resource (which can mutate).
#
# Recreate:
doctl kubernetes cluster node-pool create CLUSTER_ID \
  --name "%s-tagged" --size s-2vcpu-4gb --count 2 \
  --tag "env:production" --tag "pool:%s"

# Then drain + delete the old pool:
doctl kubernetes cluster node-pool delete CLUSTER_ID %s --force`, pool, pool, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Drain workloads before deleting the old pool to avoid downtime.",
	}, nil
}

func renderDoctlDOKSSize(f compliancekit.Finding) (remediate.Snippet, error) {
	pool := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# Recreate the pool on a supported size.
doctl kubernetes cluster node-pool create CLUSTER_ID \
  --name "%s-new" --size s-2vcpu-4gb --count 2

# Drain the old pool then delete:
kubectl drain --selector doks.digitalocean.com/node-pool=%s --ignore-daemonsets --delete-emptydir-data
doctl kubernetes cluster node-pool delete CLUSTER_ID %s --force`, pool, pool, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Coordinate the drain window with on-call. PDBs (PodDisruptionBudgets) on critical workloads will block drain if min available is too tight.",
	}, nil
}

func renderDoctlDOKSMaintenance(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# Pick a low-traffic hour. UTC; convert from your primary timezone.
doctl kubernetes cluster update %s --maintenance-window=sunday=04:00`, c)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster get %s --format MaintenancePolicy", c),
	}, nil
}

func renderDoctlDOKSLogging(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# 1. Save kubeconfig:
doctl kubernetes cluster kubeconfig save %s

# 2. Install fluent-bit (DaemonSet) forwarding to a log sink:
helm repo add fluent https://fluent.github.io/helm-charts
helm install fluent-bit fluent/fluent-bit --namespace logging --create-namespace

# 3. Verify forwarding:
kubectl -n logging logs -l app.kubernetes.io/name=fluent-bit --tail=20`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Configure outputs (Loki, Datadog, Splunk) via Helm values. Aim for ≥90d retention.",
		Refs:  []string{"https://docs.fluentbit.io/manual/installation/kubernetes"},
	}, nil
}

func renderDoctlDOKSMetricsServer(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`doctl kubernetes cluster kubeconfig save %s

# Check if already present:
kubectl -n kube-system get deployment metrics-server || \
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`, c)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n kube-system get deployment metrics-server",
		Notes:     "Idempotent: install only fires if missing. DOKS may need --kubelet-insecure-tls in the deployment args.",
	}, nil
}

func renderDoctlDOKSCertManager(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`doctl kubernetes cluster kubeconfig save %s

helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true

# Then create a ClusterIssuer for Let's Encrypt with DNS01 webhook:
kubectl apply -f - <<'YAML'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: letsencrypt-prod }
spec:
  acme:
    email: secops@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef: { name: letsencrypt-prod-key }
    solvers:
      - http01: { ingress: { class: nginx } }
YAML`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n cert-manager get deployment cert-manager",
		Notes:     "Switch http01 → dns01 via cert-manager-webhook-digitalocean if you need wildcard certs.",
	}, nil
}

func renderDoctlDOKSAutoscaler(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`# Enable native per-pool autoscaling (sufficient for most clusters).
doctl kubernetes cluster node-pool update %s POOL_NAME \
  --auto-scale --min-nodes=2 --max-nodes=10`, c)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster node-pool list %s --format Name,AutoScale,Min,Max", c),
	}, nil
}

func renderDoctlDOKSPSA(f compliancekit.Finding) (remediate.Snippet, error) {
	c := doctlDOKSCluster(f)
	body := fmt.Sprintf(`doctl kubernetes cluster kubeconfig save %s

# Label production namespace with PSA enforcement (start at warn, flip enforce after 2 weeks).
kubectl label ns production \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted --overwrite`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl get ns production -o jsonpath='{.metadata.labels}'",
		Notes:     "Test in non-prod first; PSA enforce can refuse deployments that worked under PSP.",
	}, nil
}
