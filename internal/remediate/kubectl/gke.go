package kubectl

// v0.21 phase 10 — kubectl backfill for the 13 GKE legacy check
// IDs. Sits alongside managed_extra.go (Phase 8 GKE deepening
// additions). See backfill_helper.go for the shared renderer.

func init() {
	registerBackfillIDs(
		"k8s-gke-binary-authorization",
		"k8s-gke-legacy-abac",
		"k8s-gke-logging-monitoring",
		"k8s-gke-master-authorized-networks",
		"k8s-gke-network-policy",
		"k8s-gke-nodepool-auto-repair",
		"k8s-gke-nodepool-auto-upgrade",
		"k8s-gke-nodepool-cos",
		"k8s-gke-nodepool-default-sa",
		"k8s-gke-private-cluster",
		"k8s-gke-release-channel",
		"k8s-gke-shielded-nodes",
		"k8s-gke-workload-identity",
	)
}
