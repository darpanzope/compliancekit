package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkJob(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":     "default",
		"backoff_limit": int32(3),
		"owner_kind":    "",
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.job.prod.default." + name,
		Type:       k8scol.JobType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkCronJob(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":                 "default",
		"schedule":                  "*/5 * * * *",
		"concurrency_policy":        "Forbid",
		"suspend":                   false,
		"starting_deadline_seconds": int64(200),
		"successful_jobs_history":   int32(3),
		"failed_jobs_history":       int32(5),
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.cronjob.prod.default." + name,
		Type:       k8scol.CronJobType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func TestJobBackoffLimit(t *testing.T) {
	g := newPodGraph(
		mkJob("good", nil),
		mkJob("unset", map[string]any{"backoff_limit": int32(-1)}),
		mkJob("huge", map[string]any{"backoff_limit": int32(100)}),
		mkJob("cron-owned", map[string]any{"owner_kind": "CronJob", "backoff_limit": int32(-1)}),
	)
	got := runCheck(t, JobBackoffLimit, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["unset"] != compliancekit.StatusFail || got["huge"] != compliancekit.StatusFail {
		t.Errorf("unset/huge: %v / %v", got["unset"], got["huge"])
	}
	if got["cron-owned"] != compliancekit.StatusSkip {
		t.Errorf("cron-owned: %v (want skip)", got["cron-owned"])
	}
}

func TestCronJobConcurrency(t *testing.T) {
	g := newPodGraph(
		mkCronJob("good", nil),
		mkCronJob("replace", map[string]any{"concurrency_policy": "Replace"}),
		mkCronJob("allow", map[string]any{"concurrency_policy": "Allow"}),
		mkCronJob("empty", map[string]any{"concurrency_policy": ""}),
	)
	got := runCheck(t, CronJobConcurrency, g)
	if got["good"] != compliancekit.StatusPass || got["replace"] != compliancekit.StatusPass {
		t.Errorf("good/replace: %v / %v", got["good"], got["replace"])
	}
	if got["allow"] != compliancekit.StatusFail || got["empty"] != compliancekit.StatusFail {
		t.Errorf("allow/empty: %v / %v", got["allow"], got["empty"])
	}
}

func TestCronJobHistoryLimit(t *testing.T) {
	g := newPodGraph(
		mkCronJob("good", nil),
		mkCronJob("missing-success", map[string]any{"successful_jobs_history": int32(-1)}),
		mkCronJob("missing-failed", map[string]any{"failed_jobs_history": int32(-1)}),
	)
	got := runCheck(t, CronJobHistoryLimit, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["missing-success"] != compliancekit.StatusFail || got["missing-failed"] != compliancekit.StatusFail {
		t.Errorf("missing-*: %v / %v", got["missing-success"], got["missing-failed"])
	}
}

func TestCronJobStartingDeadline(t *testing.T) {
	g := newPodGraph(
		mkCronJob("good", nil),
		mkCronJob("unset", map[string]any{"starting_deadline_seconds": int64(-1)}),
		mkCronJob("zero", map[string]any{"starting_deadline_seconds": int64(0)}),
	)
	got := runCheck(t, CronJobStartingDeadline, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["unset"] != compliancekit.StatusFail || got["zero"] != compliancekit.StatusFail {
		t.Errorf("unset/zero: %v / %v", got["unset"], got["zero"])
	}
}
