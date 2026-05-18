package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// ----- Multiple default StorageClasses --------------------------

var CheckSCDefaultMultiple = compliancekit.Check{
	ID:           "k8s-storageclass-default-multiple",
	Title:        "Only one StorageClass should be marked default",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.StorageClassType,
	Description: "When multiple StorageClasses carry the " +
		"`storageclass.kubernetes.io/is-default-class: true` " +
		"annotation, the cluster's behavior on a PVC without " +
		"`storageClassName` is undefined — it picks whichever the " +
		"admission plugin sees first, which can change at upgrade time. " +
		"Exactly one default is correct; zero defaults forces every " +
		"PVC to declare its class.",
	Remediation: "Set the annotation to `false` on every StorageClass " +
		"except the intended default.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "storage", "hygiene"},
	Scanner: "storage.SCDefaultMultiple",
}

func SCDefaultMultiple(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	defaults := []string{}
	for _, sc := range g.ByType(k8scol.StorageClassType) {
		if d, _ := sc.Attributes["is_default"].(bool); d {
			defaults = append(defaults, sc.Name)
		}
	}
	findings := []compliancekit.Finding{}
	for _, sc := range g.ByType(k8scol.StorageClassType) {
		f := compliancekit.Finding{
			CheckID:  CheckSCDefaultMultiple.ID,
			Severity: CheckSCDefaultMultiple.Severity,
			Resource: sc.Ref(),
			Tags:     CheckSCDefaultMultiple.Tags,
		}
		isDefault, _ := sc.Attributes["is_default"].(bool)
		switch {
		case !isDefault:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("storageclass %q: not default", sc.Name)
		case len(defaults) == 1:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("storageclass %q: sole default", sc.Name)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("storageclass %q: one of %d defaults", sc.Name, len(defaults))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- StorageClass encryption ---------------------------------

var CheckSCEncryption = compliancekit.Check{
	ID:           "k8s-storageclass-encryption",
	Title:        "StorageClasses should configure at-rest encryption",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.StorageClassType,
	Description: "Disk encryption at rest is the baseline for any data-" +
		"bearing workload. The CSI parameters that enable it vary by " +
		"driver — AWS EBS uses `encrypted: true` (and optionally " +
		"`kmsKeyId`), GCP PD uses `disk-encryption-kms-key`, Azure " +
		"Disk uses `diskEncryptionSetID`. A StorageClass that omits " +
		"all of these provisions unencrypted volumes.",
	Remediation: "Add the driver-specific encryption parameter. For " +
		"AWS EBS: `parameters.encrypted: \"true\"`. For GCP PD: " +
		"`parameters.disk-encryption-kms-key: projects/.../keys/...`. " +
		"For Azure: `parameters.diskEncryptionSetID: ...`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.8.24"},
		"cis-v8":   {"3.11", "11.3"},
	},
	Tags:    []string{"k8s", "storage", "encryption"},
	Scanner: "storage.SCEncryption",
}

func SCEncryption(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, sc := range g.ByType(k8scol.StorageClassType) {
		hasEnc, _ := sc.Attributes["has_encryption"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckSCEncryption.ID,
			Severity: CheckSCEncryption.Severity,
			Resource: sc.Ref(),
			Tags:     CheckSCEncryption.Tags,
		}
		if hasEnc {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("storageclass %q: encryption parameter set", sc.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("storageclass %q: no encryption parameter", sc.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- StorageClass reclaim policy ------------------------------

var CheckSCReclaimPolicy = compliancekit.Check{
	ID:           "k8s-storageclass-reclaim-policy",
	Title:        "StorageClasses for data-bearing workloads should set reclaimPolicy: Retain",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.StorageClassType,
	Description: "The default StorageClass reclaim policy is `Delete`, " +
		"which destroys the underlying volume when its PVC is deleted. " +
		"That is correct for ephemeral workloads (CI scratch, cache) " +
		"but a data-loss hazard for databases and stateful apps. " +
		"`Retain` keeps the volume around so an operator can rebind " +
		"or backup before deletion.",
	Remediation: "Define a separate StorageClass for stateful workloads " +
		"with `reclaimPolicy: Retain`. Leave Delete for ephemeral " +
		"classes.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "storage", "reclaim"},
	Scanner: "storage.SCReclaimPolicy",
}

func SCReclaimPolicy(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, sc := range g.ByType(k8scol.StorageClassType) {
		reclaim, _ := sc.Attributes["reclaim_policy"].(string)
		// Empty means "Delete" per K8s default.
		actual := reclaim
		if actual == "" {
			actual = "Delete"
		}
		f := compliancekit.Finding{
			CheckID:  CheckSCReclaimPolicy.ID,
			Severity: CheckSCReclaimPolicy.Severity,
			Resource: sc.Ref(),
			Tags:     CheckSCReclaimPolicy.Tags,
		}
		if actual == "Retain" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("storageclass %q: reclaimPolicy=Retain", sc.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("storageclass %q: reclaimPolicy=%s (data-loss risk for stateful workloads)", sc.Name, actual)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PV retain not set ----------------------------------------

var CheckPVRetain = compliancekit.Check{
	ID:           "k8s-pv-reclaim-retain",
	Title:        "PersistentVolumes for stateful claims should set reclaimPolicy: Retain",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeType,
	Description: "Same data-loss risk as the StorageClass check but " +
		"flagged at the PV level so manually-provisioned volumes (no " +
		"StorageClass) are still covered.",
	Remediation: "`kubectl patch pv <name> -p '{\"spec\": " +
		"{\"persistentVolumeReclaimPolicy\": \"Retain\"}}'`. For " +
		"dynamically-provisioned volumes, fix the StorageClass instead " +
		"so new PVs inherit Retain.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "storage", "reclaim"},
	Scanner: "storage.PVRetain",
}

func PVRetain(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, pv := range g.ByType(k8scol.PersistentVolumeType) {
		reclaim, _ := pv.Attributes["reclaim_policy"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckPVRetain.ID,
			Severity: CheckPVRetain.Severity,
			Resource: pv.Ref(),
			Tags:     CheckPVRetain.Tags,
		}
		if reclaim == "Retain" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pv %q: reclaim=Retain", pv.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pv %q: reclaim=%s", pv.Name, reclaim)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PV encrypted hint ----------------------------------------

var CheckPVEncrypted = compliancekit.Check{
	ID:           "k8s-pv-encryption-hint",
	Title:        "PersistentVolumes should carry an encryption hint",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeType,
	Description: "Compliancekit cannot guarantee a PV is encrypted (CSI " +
		"drivers report differently) but can detect the canonical " +
		"hints — `encrypted=true` in CSI volumeAttributes, KMS key " +
		"references, or the `compliancekit.io/encrypted=true` label. " +
		"A PV with none of these is most likely unencrypted.",
	Remediation: "Apply the `compliancekit.io/encrypted: \"true\"` " +
		"label to PVs you have verified out-of-band, or migrate the " +
		"workload onto a StorageClass with encryption parameters " +
		"configured.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.8.24"},
		"cis-v8":   {"3.11", "11.3"},
	},
	Tags:    []string{"k8s", "storage", "encryption"},
	Scanner: "storage.PVEncrypted",
}

func PVEncrypted(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, pv := range g.ByType(k8scol.PersistentVolumeType) {
		hint, _ := pv.Attributes["has_encryption_hint"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckPVEncrypted.ID,
			Severity: CheckPVEncrypted.Severity,
			Resource: pv.Ref(),
			Tags:     CheckPVEncrypted.Tags,
		}
		if hint {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pv %q: encryption hint detected", pv.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pv %q: no encryption hint", pv.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PV orphan (released) ------------------------------------

var CheckPVOrphan = compliancekit.Check{
	ID:           "k8s-pv-orphan",
	Title:        "Released PersistentVolumes should be cleaned up",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeType,
	Description: "A PV in `Released` phase has lost its claim but still " +
		"exists. Without manual intervention the underlying disk keeps " +
		"billing. For Retain volumes this is by design; for Delete " +
		"volumes it usually indicates a stuck reclaim — the volume " +
		"plugin failed to clean up.",
	Remediation: "Either rebind the PV to a new PVC or delete it. " +
		"`kubectl delete pv <name>` removes the K8s object; the " +
		"underlying disk is destroyed only if reclaimPolicy=Delete.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC9.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "storage", "hygiene", "cost"},
	Scanner: "storage.PVOrphan",
}

func PVOrphan(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, pv := range g.ByType(k8scol.PersistentVolumeType) {
		phase, _ := pv.Attributes["phase"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckPVOrphan.ID,
			Severity: CheckPVOrphan.Severity,
			Resource: pv.Ref(),
			Tags:     CheckPVOrphan.Tags,
		}
		switch phase {
		case "Released":
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pv %q: Released (orphan)", pv.Name)
		case "Failed":
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pv %q: Failed", pv.Name)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pv %q: phase=%s", pv.Name, phase)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PVC not bound -------------------------------------------

var CheckPVCNotBound = compliancekit.Check{
	ID:           "k8s-pvc-not-bound",
	Title:        "PersistentVolumeClaims should be Bound",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeClaimType,
	Description: "A PVC stuck in `Pending` phase indicates the cluster " +
		"could not provision matching storage — either no StorageClass " +
		"with the right capacity / access mode, or the CSI driver " +
		"failed. Pods that mount the PVC stay Pending forever.",
	Remediation: "`kubectl describe pvc <name>` shows the controller " +
		"message. Common fixes: switch StorageClass, request a smaller " +
		"size, ensure the CSI driver pod is healthy.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "storage", "reliability"},
	Scanner: "storage.PVCNotBound",
}

func PVCNotBound(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, pvc := range g.ByType(k8scol.PersistentVolumeClaimType) {
		phase, _ := pvc.Attributes["phase"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckPVCNotBound.ID,
			Severity: CheckPVCNotBound.Severity,
			Resource: pvc.Ref(),
			Tags:     CheckPVCNotBound.Tags,
		}
		if phase == "Bound" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pvc %q: Bound", secretDesc(pvc))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pvc %q: phase=%s", secretDesc(pvc), phase)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PVC orphan (bound but not used) -------------------------

var CheckPVCOrphan = compliancekit.Check{
	ID:           "k8s-pvc-orphan",
	Title:        "Bound PersistentVolumeClaims should be mounted by at least one pod",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeClaimType,
	Description: "A PVC bound to a real PV but mounted by zero pods is " +
		"paying for storage nobody uses. Common after a Deployment is " +
		"deleted but PVCs were not — the storage class's reclaim " +
		"policy keeps the disk around. Audit and delete.",
	Remediation: "For PVCs you've confirmed are truly unused: " +
		"`kubectl delete pvc <name> -n <ns>`. Make sure the underlying " +
		"PV's reclaim policy matches your intent before deleting.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC9.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "storage", "cost"},
	Scanner: "storage.PVCOrphan",
}

func PVCOrphan(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	// Pods reference PVCs via volumes; the workload collector does not
	// yet capture that. Phase 6 will tighten this; for now use a
	// namespace-coverage heuristic.
	usedNS := map[string]struct{}{}
	for _, p := range g.ByType(k8scol.PodType) {
		ns, _ := p.Attributes["namespace"].(string)
		usedNS[ns] = struct{}{}
	}
	findings := []compliancekit.Finding{}
	for _, pvc := range g.ByType(k8scol.PersistentVolumeClaimType) {
		phase, _ := pvc.Attributes["phase"].(string)
		if phase != "Bound" {
			continue
		}
		ns, _ := pvc.Attributes["namespace"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckPVCOrphan.ID,
			Severity: CheckPVCOrphan.Severity,
			Resource: pvc.Ref(),
			Tags:     CheckPVCOrphan.Tags,
		}
		if _, used := usedNS[ns]; used {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pvc %q: namespace has pods (per-PVC tracking lands Phase 6)", secretDesc(pvc))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pvc %q: bound but namespace has no pods", secretDesc(pvc))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- PVC access modes ----------------------------------------

var CheckPVCRWX = compliancekit.Check{
	ID:           "k8s-pvc-readwritemany",
	Title:        "PVCs using ReadWriteMany should be documented",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "storage",
	ResourceType: k8scol.PersistentVolumeClaimType,
	Description: "ReadWriteMany access mode lets multiple pods write to " +
		"the same volume concurrently. Few CSI drivers support it well " +
		"(NFS, EFS, Azure Files, CephFS). Pods that use it must " +
		"coordinate concurrent writes — a common source of subtle " +
		"data-corruption bugs. Informational; flag for review.",
	Remediation: "Confirm the workload's concurrency model handles RWX " +
		"correctly. Where possible, prefer one-writer-many-readers " +
		"(RWO + an internal sync) over RWX.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "storage", "rwx", "informational"},
	Scanner: "storage.PVCRWX",
}

func PVCRWX(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, pvc := range g.ByType(k8scol.PersistentVolumeClaimType) {
		modes, _ := pvc.Attributes["access_modes"].([]string)
		hasRWX := false
		for _, m := range modes {
			if m == "ReadWriteMany" {
				hasRWX = true
				break
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckPVCRWX.ID,
			Severity: CheckPVCRWX.Severity,
			Resource: pvc.Ref(),
			Tags:     CheckPVCRWX.Tags,
		}
		if hasRWX {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pvc %q: uses ReadWriteMany", secretDesc(pvc))
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pvc %q: access_modes=%v", secretDesc(pvc), modes)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- init ----------------------------------------------------

func init() {
	compliancekit.Register(CheckSCDefaultMultiple, SCDefaultMultiple)
	compliancekit.Register(CheckSCEncryption, SCEncryption)
	compliancekit.Register(CheckSCReclaimPolicy, SCReclaimPolicy)
	compliancekit.Register(CheckPVRetain, PVRetain)
	compliancekit.Register(CheckPVEncrypted, PVEncrypted)
	compliancekit.Register(CheckPVOrphan, PVOrphan)
	compliancekit.Register(CheckPVCNotBound, PVCNotBound)
	compliancekit.Register(CheckPVCOrphan, PVCOrphan)
	compliancekit.Register(CheckPVCRWX, PVCRWX)
}
