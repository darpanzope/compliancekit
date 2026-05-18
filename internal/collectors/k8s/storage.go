package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// collectStorage fetches Secrets, ConfigMaps, PVs, PVCs, and
// StorageClasses. Secrets carry runtime credentials; PV/PVC/SC are
// the persistent-storage configuration surface.
func (c *Collector) collectStorage(ctx context.Context, scope *ContextScope) ([]compliancekit.Resource, error) {
	out := make([]compliancekit.Resource, 0, 64)

	secrets, err := listSecrets(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	for i := range secrets {
		out = append(out, c.secretResource(scope, &secrets[i]))
	}

	cms, err := listConfigMaps(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list configmaps: %w", err)
	}
	for i := range cms {
		out = append(out, c.configMapResource(scope, &cms[i]))
	}

	scs, err := scope.Client.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list storageclasses: %w", err)
	}
	for i := range scs.Items {
		out = append(out, c.storageClassResource(scope, &scs.Items[i]))
	}

	pvs, err := scope.Client.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pvs: %w", err)
	}
	for i := range pvs.Items {
		out = append(out, c.persistentVolumeResource(scope, &pvs.Items[i]))
	}

	pvcs, err := listPVCs(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list pvcs: %w", err)
	}
	for i := range pvcs {
		out = append(out, c.persistentVolumeClaimResource(scope, &pvcs[i]))
	}

	return out, nil
}

func listSecrets(ctx context.Context, scope *ContextScope) ([]corev1.Secret, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterSecretsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.Secret, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterSecretsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterSecretsByExclude(in []corev1.Secret, ex []string) []corev1.Secret {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.Secret, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listConfigMaps(ctx context.Context, scope *ContextScope) ([]corev1.ConfigMap, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterCMsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.ConfigMap, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterCMsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterCMsByExclude(in []corev1.ConfigMap, ex []string) []corev1.ConfigMap {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.ConfigMap, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listPVCs(ctx context.Context, scope *ContextScope) ([]corev1.PersistentVolumeClaim, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterPVCsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.PersistentVolumeClaim, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterPVCsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterPVCsByExclude(in []corev1.PersistentVolumeClaim, ex []string) []corev1.PersistentVolumeClaim {
	if len(ex) == 0 {
		return in
	}
	out := make([]corev1.PersistentVolumeClaim, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

// ---- Resource builders ----

func (c *Collector) secretResource(scope *ContextScope, s *corev1.Secret) compliancekit.Resource {
	totalSize := 0
	keys := make([]string, 0, len(s.Data))
	for k, v := range s.Data {
		keys = append(keys, k)
		totalSize += len(v)
	}
	attrs := map[string]any{
		"namespace":   s.Namespace,
		"type":        string(s.Type),
		"size_bytes":  totalSize,
		"keys":        keys,
		"key_count":   len(keys),
		"owner_kind":  firstOwnerKind(s.OwnerReferences),
		"owner_name":  firstOwnerName(s.OwnerReferences),
		"annotations": copyStringMap(s.Annotations),
		"labels":      copyStringMap(s.Labels),
		"for_sa_name": s.Annotations["kubernetes.io/service-account.name"],
		"immutable":   boolOrFalse(s.Immutable),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", SecretType, scope.Name, s.Namespace, s.Name),
		Type:       SecretType,
		Name:       s.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) configMapResource(scope *ContextScope, cm *corev1.ConfigMap) compliancekit.Resource {
	totalSize := 0
	keys := make([]string, 0, len(cm.Data))
	for k, v := range cm.Data {
		keys = append(keys, k)
		totalSize += len(v)
	}
	attrs := map[string]any{
		"namespace":  cm.Namespace,
		"size_bytes": totalSize,
		"keys":       keys,
		"key_count":  len(keys),
		"owner_kind": firstOwnerKind(cm.OwnerReferences),
		"labels":     copyStringMap(cm.Labels),
		"immutable":  boolOrFalse(cm.Immutable),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", ConfigMapType, scope.Name, cm.Namespace, cm.Name),
		Type:       ConfigMapType,
		Name:       cm.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) storageClassResource(scope *ContextScope, sc *storagev1.StorageClass) compliancekit.Resource {
	reclaim := ""
	if sc.ReclaimPolicy != nil {
		reclaim = string(*sc.ReclaimPolicy)
	}
	volumeBinding := ""
	if sc.VolumeBindingMode != nil {
		volumeBinding = string(*sc.VolumeBindingMode)
	}
	allowExpand := boolOrFalse(sc.AllowVolumeExpansion)

	attrs := map[string]any{
		"provisioner":         sc.Provisioner,
		"is_default":          truthyValue(sc.Annotations["storageclass.kubernetes.io/is-default-class"]),
		"reclaim_policy":      reclaim,
		"volume_binding_mode": volumeBinding,
		"allow_volume_expand": allowExpand,
		"parameters":          copyStringMap(sc.Parameters),
		"has_encryption":      hasEncryptionParam(sc.Parameters),
		"labels":              copyStringMap(sc.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", StorageClassType, scope.Name, sc.Name),
		Type:       StorageClassType,
		Name:       sc.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) persistentVolumeResource(scope *ContextScope, pv *corev1.PersistentVolume) compliancekit.Resource {
	capacity := ""
	if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
		capacity = q.String()
	}
	claimNS, claimName := "", ""
	if pv.Spec.ClaimRef != nil {
		claimNS = pv.Spec.ClaimRef.Namespace
		claimName = pv.Spec.ClaimRef.Name
	}
	attrs := map[string]any{
		"storage_class_name":  pv.Spec.StorageClassName,
		"reclaim_policy":      string(pv.Spec.PersistentVolumeReclaimPolicy),
		"capacity":            capacity,
		"phase":               string(pv.Status.Phase),
		"claim_namespace":     claimNS,
		"claim_name":          claimName,
		"access_modes":        flattenAccessModes(pv.Spec.AccessModes),
		"has_encryption_hint": pvHasEncryptionHint(pv),
		"volume_mode":         pvVolumeMode(pv),
		"labels":              copyStringMap(pv.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", PersistentVolumeType, scope.Name, pv.Name),
		Type:       PersistentVolumeType,
		Name:       pv.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

func (c *Collector) persistentVolumeClaimResource(scope *ContextScope, pvc *corev1.PersistentVolumeClaim) compliancekit.Resource {
	storageClassName := ""
	if pvc.Spec.StorageClassName != nil {
		storageClassName = *pvc.Spec.StorageClassName
	}
	requested := ""
	if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		requested = req.String()
	}
	attrs := map[string]any{
		"namespace":          pvc.Namespace,
		"storage_class_name": storageClassName,
		"phase":              string(pvc.Status.Phase),
		"requested":          requested,
		"volume_name":        pvc.Spec.VolumeName,
		"access_modes":       flattenAccessModes(pvc.Spec.AccessModes),
		"labels":             copyStringMap(pvc.Labels),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", PersistentVolumeClaimType, scope.Name, pvc.Namespace, pvc.Name),
		Type:       PersistentVolumeClaimType,
		Name:       pvc.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: scope.AccountID(), Region: scope.Region()})
	return r
}

// ---- Helpers ----

func flattenAccessModes(modes []corev1.PersistentVolumeAccessMode) []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return out
}

// truthyValue reports whether the string represents a true-ish flag.
// Avoids a goconst lint hit on the repeated "true" literal.
func truthyValue(v string) bool {
	return v == "true" || v == "True"
}

// hasEncryptionParam returns true when the StorageClass parameters
// contain any key suggesting encryption is configured. CSI drivers
// vary in key naming: AWS EBS uses "encrypted", GCP PD uses
// "disk-encryption-kms-key", Azure Disk uses "diskEncryptionSetID".
func hasEncryptionParam(params map[string]string) bool {
	for k, v := range params {
		lk := strings.ToLower(k)
		switch {
		case strings.Contains(lk, "encrypted") && truthyValue(v):
			return true
		case strings.Contains(lk, "kms"):
			return true
		case strings.Contains(lk, "diskencryptionset"):
			return true
		case strings.Contains(lk, "encryption"):
			return true
		}
	}
	return false
}

// pvHasEncryptionHint returns true when a PV's spec contains
// driver-specific hints suggesting the underlying volume is encrypted.
// PVs do not have a uniform encryption flag — different CSI drivers
// stash the info in different places. We surface the heuristic so
// checks can run with conservative defaults; operators can override
// via labels for explicit guarantees.
func pvHasEncryptionHint(pv *corev1.PersistentVolume) bool {
	if pv.Spec.CSI != nil {
		for k, v := range pv.Spec.CSI.VolumeAttributes {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "encrypted") || strings.Contains(lk, "kms") {
				if truthyValue(v) || strings.HasPrefix(v, "projects/") || strings.HasPrefix(v, "arn:") {
					return true
				}
			}
		}
	}
	// Label-based opt-in: operators can mark PVs as encrypted with a
	// label so the heuristic does not need to know every driver
	// convention.
	if truthyValue(pv.Labels["compliancekit.io/encrypted"]) {
		return true
	}
	return false
}

func pvVolumeMode(pv *corev1.PersistentVolume) string {
	if pv.Spec.VolumeMode == nil {
		return ""
	}
	return string(*pv.Spec.VolumeMode)
}
