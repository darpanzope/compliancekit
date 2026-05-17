package kubectl

// v0.21 phase 10 — kubectl backfill for the 8 Secret / ConfigMap /
// ServiceAccount legacy check IDs.

func init() {
	registerBackfillIDs(
		"k8s-configmap-secret-shaped-data",
		"k8s-configmap-too-large",
		"k8s-sa-default-used",
		"k8s-sa-imagepull-secrets-set",
		"k8s-sa-orphan",
		"k8s-secret-immutable",
		"k8s-secret-orphan",
		"k8s-secret-too-large",
	)
}
