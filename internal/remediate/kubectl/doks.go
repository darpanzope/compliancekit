package kubectl

// v0.21 phase 10 — kubectl backfill for the 19 DOKS legacy check
// IDs. Each pulls the per-check Remediation from the Check struct
// + prefixes a `doctl kubernetes cluster get` audit command (see
// backfill_helper.go for the shared renderer).
//
// Sits alongside managed_extra.go (v0.21 phase 8 DOKS deepening
// additions) so the operator can find every DOKS-related kubectl
// strategy in one of two files per the v0.22 600-LoC invariant.

func init() {
	registerBackfillIDs(
		"k8s-doks-auto-upgrade",
		"k8s-doks-cert-manager-installed",
		"k8s-doks-cluster-autoscaler-eligible",
		"k8s-doks-cluster-running",
		"k8s-doks-control-plane-logging-exported",
		"k8s-doks-ha-control-plane",
		"k8s-doks-maintenance-window",
		"k8s-doks-maintenance-window-loud-hours",
		"k8s-doks-metrics-server-installed",
		"k8s-doks-nodepool-autoscale",
		"k8s-doks-nodepool-min-nodes",
		"k8s-doks-nodepool-no-environment-tag",
		"k8s-doks-nodepool-no-taints",
		"k8s-doks-nodepool-size-retired",
		"k8s-doks-pod-security-standards-baseline",
		"k8s-doks-registry-integration",
		"k8s-doks-surge-upgrade",
		"k8s-doks-version-deprecated",
		"k8s-doks-vpc-attached",
	)
}
