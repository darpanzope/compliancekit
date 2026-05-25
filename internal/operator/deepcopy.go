package operator

// Hand-written DeepCopy implementations. controller-gen would emit
// these automatically; for v1.15.0 we keep the dep surface to
// controller-runtime + apimachinery and write the four methods by
// hand. Two CRDs × (object + list) = four DeepCopy / DeepCopyObject
// + four DeepCopy methods, plus the spec/status DeepCopy helpers
// they call.

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// ── ComplianceSchedule ───────────────────────────────────────────

// DeepCopyInto copies the receiver into out.
func (in *ComplianceSchedule) DeepCopyInto(out *ComplianceSchedule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a clone of the receiver.
func (in *ComplianceSchedule) DeepCopy() *ComplianceSchedule {
	if in == nil {
		return nil
	}
	out := new(ComplianceSchedule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ComplianceSchedule) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopyInto copies the spec.
func (in *ComplianceScheduleSpec) DeepCopyInto(out *ComplianceScheduleSpec) {
	*out = *in
	if in.Providers != nil {
		out.Providers = make([]string, len(in.Providers))
		copy(out.Providers, in.Providers)
	}
	out.DaemonRef = in.DaemonRef
	if in.Enabled != nil {
		v := *in.Enabled
		out.Enabled = &v
	}
}

// DeepCopyInto copies the status.
func (in *ComplianceScheduleStatus) DeepCopyInto(out *ComplianceScheduleStatus) {
	*out = *in
	if in.LastRunTime != nil {
		out.LastRunTime = in.LastRunTime.DeepCopy()
	}
	if in.NextRunTime != nil {
		out.NextRunTime = in.NextRunTime.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metaCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyInto copies the list.
func (in *ComplianceScheduleList) DeepCopyInto(out *ComplianceScheduleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ComplianceSchedule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a clone of the receiver.
func (in *ComplianceScheduleList) DeepCopy() *ComplianceScheduleList {
	if in == nil {
		return nil
	}
	out := new(ComplianceScheduleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ComplianceScheduleList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// ── ScanJob ──────────────────────────────────────────────────────

// DeepCopyInto copies the receiver into out.
func (in *ScanJob) DeepCopyInto(out *ScanJob) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a clone of the receiver.
func (in *ScanJob) DeepCopy() *ScanJob {
	if in == nil {
		return nil
	}
	out := new(ScanJob)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ScanJob) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// DeepCopyInto copies the spec.
func (in *ScanJobSpec) DeepCopyInto(out *ScanJobSpec) {
	*out = *in
	if in.Args != nil {
		out.Args = make([]string, len(in.Args))
		copy(out.Args, in.Args)
	}
}

// DeepCopyInto copies the status.
func (in *ScanJobStatus) DeepCopyInto(out *ScanJobStatus) {
	*out = *in
	if in.StartTime != nil {
		out.StartTime = in.StartTime.DeepCopy()
	}
	if in.CompletionTime != nil {
		out.CompletionTime = in.CompletionTime.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metaCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyInto copies the list.
func (in *ScanJobList) DeepCopyInto(out *ScanJobList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ScanJob, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a clone of the receiver.
func (in *ScanJobList) DeepCopy() *ScanJobList {
	if in == nil {
		return nil
	}
	out := new(ScanJobList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *ScanJobList) DeepCopyObject() runtime.Object { return in.DeepCopy() }
