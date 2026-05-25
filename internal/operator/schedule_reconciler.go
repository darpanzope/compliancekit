package operator

// ComplianceSchedule reconciler. Every schedule maps to a cron
// expression; on each tick the operator POSTs /api/v1/scans/trigger
// against the configured daemon. Status is stamped with the last
// run + the next planned run.
//
// Production deployments wire this against a daemon installed via
// the v1.15 phase 1 Helm chart; the bearer token comes from a
// Secret the schedule references via SecretKeyRef.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ScheduleReconciler watches ComplianceSchedule CRs.
type ScheduleReconciler struct {
	client.Client
	HTTP *http.Client
}

// Reconcile triggers a scan if the schedule is due.
func (r *ScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("schedule", req.NamespacedName)
	var schedule ComplianceSchedule
	if err := r.Get(ctx, req.NamespacedName, &schedule); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if schedule.Spec.Enabled != nil && !*schedule.Spec.Enabled {
		logger.V(1).Info("schedule disabled; skipping")
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	spec, err := cron.ParseStandard(schedule.Spec.CronExpr)
	if err != nil {
		return r.markFailure(ctx, &schedule, "InvalidCronExpr", err)
	}
	now := time.Now().UTC()
	next := spec.Next(now)
	lastRun := time.Time{}
	if schedule.Status.LastRunTime != nil {
		lastRun = schedule.Status.LastRunTime.Time
	}
	due := false
	if lastRun.IsZero() {
		// First reconcile after creation — fire if the previous
		// would-have-fired tick is within the last 5 minutes; else
		// just wait for the next.
		prev := spec.Next(now.Add(-5 * time.Minute))
		due = !prev.After(now)
	} else {
		prev := spec.Next(lastRun)
		due = !prev.After(now)
	}
	if due {
		if err := r.triggerScan(ctx, &schedule); err != nil {
			return r.markFailure(ctx, &schedule, "TriggerFailed", err)
		}
		stamp := metav1.NewTime(now)
		schedule.Status.LastRunTime = &stamp
		schedule.Status.LastStatus = "Succeeded"
		logger.Info("scan triggered", "providers", schedule.Spec.Providers)
	}
	nextMeta := metav1.NewTime(next)
	schedule.Status.NextRunTime = &nextMeta
	if err := r.Status().Update(ctx, &schedule); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Until(next)}, nil
}

// triggerScan POSTs /api/v1/scans/trigger with the spec'd providers.
func (r *ScheduleReconciler) triggerScan(ctx context.Context, s *ComplianceSchedule) error {
	url := strings.TrimRight(s.Spec.DaemonRef.URL, "/") + "/api/v1/scans/trigger"
	body := map[string]any{
		"providers": s.Spec.Providers,
		"source":    "operator/ComplianceSchedule/" + s.Namespace + "/" + s.Name,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := r.resolveBearer(ctx, s)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	c := r.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	return nil
}

// resolveBearer reads the configured Secret value.
func (r *ScheduleReconciler) resolveBearer(ctx context.Context, s *ComplianceSchedule) (string, error) {
	var sec corev1.Secret
	key := types.NamespacedName{Namespace: s.Namespace, Name: s.Spec.DaemonRef.BearerSecret.Name}
	if err := r.Get(ctx, key, &sec); err != nil {
		return "", fmt.Errorf("bearer secret: %w", err)
	}
	v, ok := sec.Data[s.Spec.DaemonRef.BearerSecret.Key]
	if !ok {
		return "", fmt.Errorf("bearer secret %s missing key %q", key, s.Spec.DaemonRef.BearerSecret.Key)
	}
	return string(v), nil
}

// markFailure stamps the status + requeues for retry.
func (r *ScheduleReconciler) markFailure(ctx context.Context, s *ComplianceSchedule, reason string, cause error) (ctrl.Result, error) {
	s.Status.LastStatus = reason + ": " + cause.Error()
	_ = r.Status().Update(ctx, s)
	return ctrl.Result{RequeueAfter: time.Minute}, cause
}

// SetupWithManager wires the reconciler into the controller-runtime
// manager.
func (r *ScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ComplianceSchedule{}).
		Complete(r)
}
