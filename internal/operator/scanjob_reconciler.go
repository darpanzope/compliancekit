package operator

// ScanJob reconciler. Each CR maps to a single Pod the operator
// creates + watches to completion. The Pod runs the compliancekit
// image with the spec'd args; status mirrors the Pod phase.
//
// One-shot semantics — the controller never re-creates a Pod on
// failure. Operators who want retries author a new ScanJob (the
// CR carries the desired-state record; cluster history shows the
// outcome).

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ScanJobReconciler watches ScanJob CRs.
type ScanJobReconciler struct {
	client.Client
	DefaultImage string // fallback when ScanJob.Spec.Image is empty
}

// Reconcile creates the per-CR Pod + mirrors its phase.
func (r *ScanJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("scanjob", req.NamespacedName)
	var job ScanJob
	if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	podName := job.Status.PodName
	if podName == "" {
		podName = job.Name + "-scan"
	}
	var pod corev1.Pod
	err := r.Get(ctx, types.NamespacedName{Namespace: job.Namespace, Name: podName}, &pod)
	switch {
	case apierrors.IsNotFound(err):
		// Create the Pod.
		built := r.buildPod(&job, podName)
		if err := r.Create(ctx, built); err != nil {
			return ctrl.Result{}, fmt.Errorf("create pod: %w", err)
		}
		now := metav1.Now()
		job.Status.PodName = podName
		job.Status.Phase = string(corev1.PodPending)
		job.Status.StartTime = &now
		if err := r.Status().Update(ctx, &job); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("pod created", "pod", podName)
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get pod: %w", err)
	}
	// Mirror the pod phase onto the CR.
	job.Status.Phase = string(pod.Status.Phase)
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		if job.Status.CompletionTime == nil {
			now := metav1.Now()
			job.Status.CompletionTime = &now
		}
	}
	if err := r.Status().Update(ctx, &job); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// buildPod renders the Pod spec from a ScanJob CR.
func (r *ScanJobReconciler) buildPod(job *ScanJob, podName string) *corev1.Pod {
	img := job.Spec.Image
	if img == "" {
		img = r.DefaultImage
	}
	args := append([]string{"scan"}, job.Spec.Args...)
	volumes := []corev1.Volume{
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "tmp", MountPath: "/tmp"},
	}
	if job.Spec.EvidencePackPVC != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "evidence",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: job.Spec.EvidencePackPVC},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "evidence", MountPath: "/work"})
	}
	c := corev1.Container{
		Name:            "compliancekit",
		Image:           img,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            args,
		VolumeMounts:    mounts,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr(false),
			ReadOnlyRootFilesystem:   ptr(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
	if job.Spec.EnvFromSecret != "" {
		c.EnvFrom = []corev1.EnvFromSource{{
			SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: job.Spec.EnvFromSecret}},
		}}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: job.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "compliancekit",
				"app.kubernetes.io/component": "scanjob",
				"compliancekit.io/scanjob":    job.Name,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: GroupVersion.String(),
				Kind:       "ScanJob",
				Name:       job.Name,
				UID:        job.UID,
				Controller: ptr(true),
			}},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				RunAsUser:      ptrInt64(65532),
				RunAsGroup:     ptrInt64(65532),
				FSGroup:        ptrInt64(65532),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{c},
			Volumes:    volumes,
		},
	}
}

// SetupWithManager wires the reconciler into the controller-runtime
// manager.
func (r *ScanJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ScanJob{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}

func ptr[T any](v T) *T       { return &v }
func ptrInt64(v int64) *int64 { return &v }
