// Package operator implements the v1.15 phase 3 K8s operator. Two
// CRDs (basic at v1.15.0; the full reconciler with profiles +
// waivers lands at v2.10 per ROADMAP):
//
//	ComplianceSchedule — operator-authored cron that fires scans
//	                     against a configured daemon URL.
//	ScanJob            — one-shot scan; the operator creates a Pod
//	                     from the spec'd compliancekit image and
//	                     watches it to completion.
//
// The operator is a thin K8s controller that bridges CRDs to either
// the daemon's REST API (ComplianceSchedule) or a fresh Pod
// (ScanJob). It deliberately does NOT manage the daemon itself —
// the Helm chart / Kustomize overlay / Terraform module is the
// daemon's install vector.
package operator

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion identifies the API group + version this package
// owns. Keep in sync with the CRD manifests under
// deploy/operator/crds/.
var GroupVersion = schema.GroupVersion{Group: "compliancekit.io", Version: "v1alpha1"}

// SchemeBuilder collects the types this package contributes for
// controller-runtime's scheme registration.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers the operator's CRD types onto s.
func AddToScheme(s *runtime.Scheme) error { return SchemeBuilder.AddToScheme(s) }

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&ComplianceSchedule{}, &ComplianceScheduleList{},
		&ScanJob{}, &ScanJobList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}

// ── ComplianceSchedule ───────────────────────────────────────────

// ComplianceSchedule fires a scan against a daemon at a cron cadence.
// The operator translates the schedule to per-tick POSTs against
// /api/v1/scans/trigger using the configured Bearer token.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ComplianceSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceScheduleSpec   `json:"spec,omitempty"`
	Status ComplianceScheduleStatus `json:"status,omitempty"`
}

// ComplianceScheduleSpec is the operator-authored payload.
type ComplianceScheduleSpec struct {
	// CronExpr is a standard 5-field cron expression (UTC unless the
	// daemon's CK_TZ overrides). robfig/cron/v3 evaluates the spec.
	CronExpr string `json:"cronExpr"`

	// Providers selects which provider scans run on each tick. Empty
	// = every provider currently enabled in the daemon.
	Providers []string `json:"providers,omitempty"`

	// DaemonRef points at a daemon instance the schedule targets.
	DaemonRef DaemonRef `json:"daemonRef"`

	// Enabled lets the operator pause / un-pause without deleting the
	// CR. Defaults true.
	Enabled *bool `json:"enabled,omitempty"`
}

// ComplianceScheduleStatus is the controller-managed half.
type ComplianceScheduleStatus struct {
	LastRunTime *metav1.Time       `json:"lastRunTime,omitempty"`
	LastStatus  string             `json:"lastStatus,omitempty"`
	NextRunTime *metav1.Time       `json:"nextRunTime,omitempty"`
	Conditions  []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ComplianceScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceSchedule `json:"items"`
}

// ── ScanJob ──────────────────────────────────────────────────────

// ScanJob requests a single one-shot scan. The operator creates a
// Pod from the spec'd image + args and watches it to completion.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ScanJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanJobSpec   `json:"spec,omitempty"`
	Status ScanJobStatus `json:"status,omitempty"`
}

// ScanJobSpec is the per-job payload.
type ScanJobSpec struct {
	// Image is the compliancekit OCI image to scan with. Defaults to
	// the operator's `image.repository:image.tag` configured at boot.
	Image string `json:"image,omitempty"`

	// Args are appended after `scan`. e.g. ["--provider=aws",
	// "--out=/tmp/findings.json"].
	Args []string `json:"args,omitempty"`

	// EvidencePackPVC mounts a PVC at /work to receive the evidence
	// pack output. Optional.
	EvidencePackPVC string `json:"evidencePackPVC,omitempty"`

	// EnvFromSecret loads env vars from a Secret (cloud creds).
	EnvFromSecret string `json:"envFromSecret,omitempty"`
}

// ScanJobStatus reflects the underlying Pod state.
type ScanJobStatus struct {
	// Phase mirrors the underlying Pod's PodPhase string
	// (Pending / Running / Succeeded / Failed / Unknown).
	Phase string `json:"phase,omitempty"`

	// PodName is the name of the Pod this CR spawned.
	PodName        string             `json:"podName,omitempty"`
	StartTime      *metav1.Time       `json:"startTime,omitempty"`
	CompletionTime *metav1.Time       `json:"completionTime,omitempty"`
	Conditions     []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ScanJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanJob `json:"items"`
}

// ── Shared types ─────────────────────────────────────────────────

// DaemonRef points at a daemon instance the schedule / scan targets.
type DaemonRef struct {
	// URL is the daemon's externally-reachable base URL.
	URL string `json:"url"`

	// BearerSecret references a Secret + key in the operator's
	// namespace whose value is the daemon API bearer token.
	BearerSecret SecretKeyRef `json:"bearerSecret"`
}

// SecretKeyRef is a (name, key) reference to a value in a Secret.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
