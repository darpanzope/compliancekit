package k8s

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// collectControllers emits Deployments, StatefulSets, DaemonSets, Jobs,
// CronJobs, and PodDisruptionBudgets — every workload controller that
// owns Pods plus the policy resource that constrains voluntary
// disruptions. Pods themselves come from collectWorkloads (phase 1).
func (c *Collector) collectControllers(ctx context.Context, scope *ContextScope) ([]compliancekit.Resource, error) {
	// Initial capacity is a guess — six kinds with some pods is in the
	// neighborhood of 32 resources on a small cluster.
	out := make([]compliancekit.Resource, 0, 32)

	deps, err := listDeployments(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deps {
		out = append(out, c.deploymentResource(scope, &deps[i]))
	}

	stss, err := listStatefulSets(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range stss {
		out = append(out, c.statefulSetResource(scope, &stss[i]))
	}

	dss, err := listDaemonSets(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range dss {
		out = append(out, c.daemonSetResource(scope, &dss[i]))
	}

	jobs, err := listJobs(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	for i := range jobs {
		out = append(out, c.jobResource(scope, &jobs[i]))
	}

	cjs, err := listCronJobs(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list cronjobs: %w", err)
	}
	for i := range cjs {
		out = append(out, c.cronJobResource(scope, &cjs[i]))
	}

	pdbs, err := listPDBs(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list pdbs: %w", err)
	}
	for i := range pdbs {
		out = append(out, c.pdbResource(scope, &pdbs[i]))
	}

	return out, nil
}

// ---- List helpers per kind. Same dual-mode (all-ns vs per-ns) pattern
// as listPods, factored through filterByNamespace + per-kind list call.

func listDeployments(ctx context.Context, scope *ContextScope) ([]appsv1.Deployment, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterDeploymentsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]appsv1.Deployment, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterDeploymentsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterDeploymentsByExclude(in []appsv1.Deployment, ex []string) []appsv1.Deployment {
	if len(ex) == 0 {
		return in
	}
	out := make([]appsv1.Deployment, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listStatefulSets(ctx context.Context, scope *ContextScope) ([]appsv1.StatefulSet, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterStatefulSetsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]appsv1.StatefulSet, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterStatefulSetsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterStatefulSetsByExclude(in []appsv1.StatefulSet, ex []string) []appsv1.StatefulSet {
	if len(ex) == 0 {
		return in
	}
	out := make([]appsv1.StatefulSet, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listDaemonSets(ctx context.Context, scope *ContextScope) ([]appsv1.DaemonSet, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterDaemonSetsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]appsv1.DaemonSet, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterDaemonSetsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterDaemonSetsByExclude(in []appsv1.DaemonSet, ex []string) []appsv1.DaemonSet {
	if len(ex) == 0 {
		return in
	}
	out := make([]appsv1.DaemonSet, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listJobs(ctx context.Context, scope *ContextScope) ([]batchv1.Job, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterJobsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]batchv1.Job, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterJobsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterJobsByExclude(in []batchv1.Job, ex []string) []batchv1.Job {
	if len(ex) == 0 {
		return in
	}
	out := make([]batchv1.Job, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listCronJobs(ctx context.Context, scope *ContextScope) ([]batchv1.CronJob, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterCronJobsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]batchv1.CronJob, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterCronJobsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterCronJobsByExclude(in []batchv1.CronJob, ex []string) []batchv1.CronJob {
	if len(ex) == 0 {
		return in
	}
	out := make([]batchv1.CronJob, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

func listPDBs(ctx context.Context, scope *ContextScope) ([]policyv1.PodDisruptionBudget, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterPDBsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]policyv1.PodDisruptionBudget, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterPDBsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterPDBsByExclude(in []policyv1.PodDisruptionBudget, ex []string) []policyv1.PodDisruptionBudget {
	if len(ex) == 0 {
		return in
	}
	out := make([]policyv1.PodDisruptionBudget, 0, len(in))
	for i := range in {
		if !contains(ex, in[i].Namespace) {
			out = append(out, in[i])
		}
	}
	return out
}

// ---- Resource builders ----

func (c *Collector) deploymentResource(scope *ContextScope, d *appsv1.Deployment) compliancekit.Resource {
	replicas := int32Or(d.Spec.Replicas, 1)
	maxUnavail, maxSurge := rollingParams(d.Spec.Strategy.RollingUpdate)
	attrs := map[string]any{
		"namespace":             d.Namespace,
		"replicas":              int(replicas),
		"ready_replicas":        int(d.Status.ReadyReplicas),
		"selector_labels":       selectorLabels(d.Spec.Selector),
		"labels":                copyStringMap(d.Labels),
		"strategy_type":         string(d.Spec.Strategy.Type),
		"max_unavailable":       maxUnavail,
		"max_surge":             maxSurge,
		"min_ready_seconds":     int(d.Spec.MinReadySeconds),
		"has_pod_anti_affinity": hasPodAntiAffinity(&d.Spec.Template.Spec),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", DeploymentType, scope.Name, d.Namespace, d.Name),
		Type:       DeploymentType,
		Name:       d.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func (c *Collector) statefulSetResource(scope *ContextScope, s *appsv1.StatefulSet) compliancekit.Resource {
	replicas := int32Or(s.Spec.Replicas, 1)
	attrs := map[string]any{
		"namespace":             s.Namespace,
		"replicas":              int(replicas),
		"ready_replicas":        int(s.Status.ReadyReplicas),
		"selector_labels":       selectorLabels(s.Spec.Selector),
		"labels":                copyStringMap(s.Labels),
		"service_name":          s.Spec.ServiceName,
		"update_strategy_type":  string(s.Spec.UpdateStrategy.Type),
		"has_pod_anti_affinity": hasPodAntiAffinity(&s.Spec.Template.Spec),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", StatefulSetType, scope.Name, s.Namespace, s.Name),
		Type:       StatefulSetType,
		Name:       s.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func (c *Collector) daemonSetResource(scope *ContextScope, d *appsv1.DaemonSet) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":               d.Namespace,
		"desired_count":           int(d.Status.DesiredNumberScheduled),
		"ready_count":             int(d.Status.NumberReady),
		"selector_labels":         selectorLabels(d.Spec.Selector),
		"labels":                  copyStringMap(d.Labels),
		"update_strategy_type":    string(d.Spec.UpdateStrategy.Type),
		"tolerates_control_plane": tolerantOfControlPlane(d.Spec.Template.Spec.Tolerations),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", DaemonSetType, scope.Name, d.Namespace, d.Name),
		Type:       DaemonSetType,
		Name:       d.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func (c *Collector) jobResource(scope *ContextScope, j *batchv1.Job) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":               j.Namespace,
		"selector_labels":         selectorLabels(j.Spec.Selector),
		"labels":                  copyStringMap(j.Labels),
		"backoff_limit":           int32Or(j.Spec.BackoffLimit, -1),
		"active_deadline_seconds": int64Or(j.Spec.ActiveDeadlineSeconds, -1),
		"parallelism":             int32Or(j.Spec.Parallelism, 1),
		"owner_kind":              firstOwnerKind(j.OwnerReferences),
		"owner_name":              firstOwnerName(j.OwnerReferences),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", JobType, scope.Name, j.Namespace, j.Name),
		Type:       JobType,
		Name:       j.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func (c *Collector) cronJobResource(scope *ContextScope, cj *batchv1.CronJob) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":                 cj.Namespace,
		"labels":                    copyStringMap(cj.Labels),
		"schedule":                  cj.Spec.Schedule,
		"concurrency_policy":        string(cj.Spec.ConcurrencyPolicy),
		"suspend":                   boolOrFalse(cj.Spec.Suspend),
		"starting_deadline_seconds": int64Or(cj.Spec.StartingDeadlineSeconds, -1),
		"successful_jobs_history":   int32Or(cj.Spec.SuccessfulJobsHistoryLimit, -1),
		"failed_jobs_history":       int32Or(cj.Spec.FailedJobsHistoryLimit, -1),
		"job_backoff_limit":         int32Or(cj.Spec.JobTemplate.Spec.BackoffLimit, -1),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", CronJobType, scope.Name, cj.Namespace, cj.Name),
		Type:       CronJobType,
		Name:       cj.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func (c *Collector) pdbResource(scope *ContextScope, p *policyv1.PodDisruptionBudget) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":       p.Namespace,
		"selector_labels": selectorLabels(p.Spec.Selector),
		"min_available":   intOrStringValue(p.Spec.MinAvailable),
		"max_unavailable": intOrStringValue(p.Spec.MaxUnavailable),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", PodDisruptionBudgetType, scope.Name, p.Namespace, p.Name),
		Type:       PodDisruptionBudgetType,
		Name:       p.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

// ---- Small helpers ----

func int32Or(p *int32, def int32) int32 {
	if p == nil {
		return def
	}
	return *p
}

func int64Or(p *int64, def int64) int64 {
	if p == nil {
		return def
	}
	return *p
}

func boolOrFalse(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func selectorLabels(sel *metav1.LabelSelector) map[string]string {
	if sel == nil {
		return map[string]string{}
	}
	return copyStringMap(sel.MatchLabels)
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func rollingParams(r *appsv1.RollingUpdateDeployment) (maxUnavail, maxSurge string) {
	if r == nil {
		return "", ""
	}
	return intOrStringValue(r.MaxUnavailable), intOrStringValue(r.MaxSurge)
}

// intOrStringValue returns the value as a string regardless of whether
// the field was an int or a string in the source YAML. K8s uses
// IntOrString in many fields (replicas, maxUnavailable, ports) and
// checks just want the rendered form.
func intOrStringValue(v any) string {
	if v == nil {
		return ""
	}
	// Use reflection-free path via fmt: IntOrString implements String().
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprintf("%v", v)
}

func hasPodAntiAffinity(spec *corev1.PodSpec) bool {
	if spec == nil || spec.Affinity == nil || spec.Affinity.PodAntiAffinity == nil {
		return false
	}
	aa := spec.Affinity.PodAntiAffinity
	return len(aa.RequiredDuringSchedulingIgnoredDuringExecution) > 0 ||
		len(aa.PreferredDuringSchedulingIgnoredDuringExecution) > 0
}

// tolerantOfControlPlane reports whether the toleration set lets the
// pod schedule on a control-plane node. This is normal for DaemonSets
// that need to monitor every node (CNI agents, log forwarders) but
// noteworthy for general DSes.
func tolerantOfControlPlane(tols []corev1.Toleration) bool {
	for _, t := range tols {
		switch t.Key {
		case "node-role.kubernetes.io/master", "node-role.kubernetes.io/control-plane":
			return true
		}
	}
	return false
}
