package kubectl

// v0.21 phase 10 — kubectl backfill for the 10 Node-level legacy
// check IDs. All emit RiskClass=Manual per backfill_helper's
// riskForBackfilledID — node-level checks reduce to either kubectl
// describe + manual intervention or node-image rebuild, neither of
// which is a one-liner.

func init() {
	registerBackfillIDs(
		"k8s-node-container-runtime",
		"k8s-node-control-plane-taint",
		"k8s-node-disk-pressure",
		"k8s-node-memory-pressure",
		"k8s-node-not-ready",
		"k8s-node-old-image",
		"k8s-node-pid-pressure",
		"k8s-node-region-label",
		"k8s-node-unschedulable",
		"k8s-node-zone-label",
	)
}
