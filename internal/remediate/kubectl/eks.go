package kubectl

// v0.21 phase 10 — kubectl backfill for the 12 EKS legacy check
// IDs. Sits alongside managed_extra.go (Phase 8 EKS deepening
// additions). See backfill_helper.go for the shared renderer.

func init() {
	registerBackfillIDs(
		"k8s-eks-authentication-mode",
		"k8s-eks-cluster-active",
		"k8s-eks-control-plane-logging",
		"k8s-eks-irsa-enabled",
		"k8s-eks-nodegroup-bottlerocket",
		"k8s-eks-nodegroup-launch-template",
		"k8s-eks-nodegroup-ssh",
		"k8s-eks-nodegroup-version-skew",
		"k8s-eks-private-endpoint",
		"k8s-eks-public-endpoint-open",
		"k8s-eks-secrets-encryption",
		"k8s-eks-version-supported",
	)
}
