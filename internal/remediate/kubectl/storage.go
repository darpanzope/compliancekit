package kubectl

// v0.21 phase 10 — kubectl backfill for the 8 PV / PVC /
// StorageClass legacy check IDs.

func init() {
	registerBackfillIDs(
		"k8s-pv-encryption-hint",
		"k8s-pv-orphan",
		"k8s-pv-reclaim-retain",
		"k8s-pvc-not-bound",
		"k8s-pvc-orphan",
		"k8s-pvc-readwritemany",
		"k8s-storageclass-default-multiple",
		"k8s-storageclass-encryption",
		"k8s-storageclass-reclaim-policy",
	)
}
