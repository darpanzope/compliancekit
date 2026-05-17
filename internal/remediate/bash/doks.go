package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 4 — bash strategies for the 10 DOKS-depth checks. Each
// strategy wraps doctl + kubectl in a POSIX-sh body with verification
// commands inline. Add-on installs use helm; control-plane logging
// uses fluent-bit; PSA uses kubectl label.

func init() {
	register("bash-doks-version-supported",
		[]string{"k8s-doks-version-deprecated"}, renderBashDOKSVersion)
	register("bash-doks-nodepool-taints",
		[]string{"k8s-doks-nodepool-no-taints"}, renderBashDOKSTaints)
	register("bash-doks-nodepool-environment-tag",
		[]string{"k8s-doks-nodepool-no-environment-tag"}, renderBashDOKSEnvTag)
	register("bash-doks-nodepool-size-supported",
		[]string{"k8s-doks-nodepool-size-retired"}, renderBashDOKSSize)
	register("bash-doks-maintenance-quiet-hours",
		[]string{"k8s-doks-maintenance-window-loud-hours"}, renderBashDOKSMaintenance)
	register("bash-doks-control-plane-logging",
		[]string{"k8s-doks-control-plane-logging-exported"}, renderBashDOKSLogging)
	register("bash-doks-metrics-server",
		[]string{"k8s-doks-metrics-server-installed"}, renderBashDOKSMetricsServer)
	register("bash-doks-cert-manager",
		[]string{"k8s-doks-cert-manager-installed"}, renderBashDOKSCertManager)
	register("bash-doks-cluster-autoscaler",
		[]string{"k8s-doks-cluster-autoscaler-eligible"}, renderBashDOKSAutoscaler)
	register("bash-doks-pod-security-standards",
		[]string{"k8s-doks-pod-security-standards-baseline"}, renderBashDOKSPSA)
}

func bashDOKSCluster(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "CLUSTER"
}

func renderBashDOKSVersion(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`# Pick the latest supported minor + upgrade in maintenance window.
cluster=%q
latest="$(doctl kubernetes options versions list -o json | jq -r '.[0].slug')"
printf 'upgrading %%s to %%s\n' "$cluster" "$latest"
doctl kubernetes cluster upgrade "$cluster" --version "$latest"`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster get %s --format Version", c),
		Notes:     "Stage in non-prod first. The script picks DO's latest available slug; pin manually if you want a specific minor.",
	}, nil
}

func renderBashDOKSTaints(f core.Finding) (remediate.Snippet, error) {
	pool := bashDOKSCluster(f)
	body := fmt.Sprintf(`pool=%q
cluster_id="$(doctl kubernetes cluster list -o json | jq -r '.[] | select(.node_pools[].name=="'"$pool"'") | .id')"
doctl kubernetes cluster node-pool update "$cluster_id" "$pool" \
  --taint "dedicated=${pool}:NoSchedule"`, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Workloads without a matching toleration won't schedule onto the pool. Existing pods are not evicted.",
	}, nil
}

func renderBashDOKSEnvTag(f core.Finding) (remediate.Snippet, error) {
	pool := bashDOKSCluster(f)
	body := fmt.Sprintf(`# doctl doesn't mutate tags on existing pools — recreate.
pool=%q
cluster_id="$(doctl kubernetes cluster list -o json | jq -r '.[] | select(.node_pools[].name=="'"$pool"'") | .id')"
doctl kubernetes cluster node-pool create "$cluster_id" \
  --name "${pool}-tagged" --size s-2vcpu-4gb --count 2 \
  --tag "env:production" --tag "pool:${pool}"

# Drain + delete old pool when ready.`, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderBashDOKSSize(f core.Finding) (remediate.Snippet, error) {
	pool := bashDOKSCluster(f)
	body := fmt.Sprintf(`pool=%q
cluster_id="$(doctl kubernetes cluster list -o json | jq -r '.[] | select(.node_pools[].name=="'"$pool"'") | .id')"

# Save kubeconfig for the drain step.
doctl kubernetes cluster kubeconfig save "$cluster_id"

# Create new pool on supported size.
doctl kubernetes cluster node-pool create "$cluster_id" \
  --name "${pool}-new" --size s-2vcpu-4gb --count 2

# Drain old pool.
kubectl drain --selector "doks.digitalocean.com/node-pool=${pool}" \
  --ignore-daemonsets --delete-emptydir-data --timeout=10m

# Delete old pool.
doctl kubernetes cluster node-pool delete "$cluster_id" "$pool" --force`, pool)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Sequence matters. Run with coordination — PDBs may block drain.",
	}, nil
}

func renderBashDOKSMaintenance(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`doctl kubernetes cluster update %s --maintenance-window=sunday=04:00`, c)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster get %s --format MaintenancePolicy", c),
	}, nil
}

func renderBashDOKSLogging(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`cluster=%q
doctl kubernetes cluster kubeconfig save "$cluster"

helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
helm upgrade --install fluent-bit fluent/fluent-bit \
  --namespace logging --create-namespace`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n logging get daemonset fluent-bit",
		Notes:     "Edit values.yaml to point the [OUTPUT] block at Loki/Datadog/Splunk.",
	}, nil
}

func renderBashDOKSMetricsServer(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`cluster=%q
doctl kubernetes cluster kubeconfig save "$cluster"
kubectl -n kube-system get deployment metrics-server >/dev/null 2>&1 || \
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`, c)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n kube-system get deployment metrics-server",
	}, nil
}

func renderBashDOKSCertManager(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`cluster=%q
doctl kubernetes cluster kubeconfig save "$cluster"

helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n cert-manager get deployment cert-manager",
	}, nil
}

func renderBashDOKSAutoscaler(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`cluster=%q
pools="$(doctl kubernetes cluster node-pool list "$cluster" -o json | jq -r '.[].name')"
for p in $pools; do
  doctl kubernetes cluster node-pool update "$cluster" "$p" \
    --auto-scale --min-nodes=2 --max-nodes=10
done`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf("doctl kubernetes cluster node-pool list %s --format Name,AutoScale,Min,Max", c),
		Notes:     "Adjust min/max per pool if some pools have different scaling needs.",
	}, nil
}

func renderBashDOKSPSA(f core.Finding) (remediate.Snippet, error) {
	c := bashDOKSCluster(f)
	body := fmt.Sprintf(`cluster=%q
doctl kubernetes cluster kubeconfig save "$cluster"

# Phase 1: warn only (no enforcement, just diagnostic). Run for 2 weeks.
kubectl label ns production \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted --overwrite

# Phase 2 (after 2 weeks of clean warn= output): flip enforce on at baseline.
# kubectl label ns production \
#   pod-security.kubernetes.io/enforce=baseline --overwrite`, c)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl get ns production -o jsonpath='{.metadata.labels}'",
		Notes:     "Two-phase rollout: warn first, enforce second. Skip warn at your peril — enforce can break production.",
	}, nil
}
