package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// jobBackoffLimitCeiling is the largest backoffLimit we accept without
// flagging. K8s defaults to 6 — anything well beyond that suggests the
// operator does not actually want the job to give up.
const jobBackoffLimitCeiling = 10

// ----- Job backoff limit -----------------------------------------

var CheckJobBackoffLimit = compliancekit.Check{
	ID:           "k8s-job-backoff-limit",
	Title:        "Jobs should set a sensible backoffLimit",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "jobs",
	ResourceType: k8scol.JobType,
	Description: "A Job with no `backoffLimit` (or an excessively large " +
		"one) retries a failing pod indefinitely, often masking a real " +
		"defect and consuming cluster capacity. The K8s default of 6 " +
		"is a reasonable ceiling; anything materially higher should " +
		"come with a documented reason.",
	Remediation: "Set `spec.backoffLimit` to between 0 and 10 depending " +
		"on whether the work is idempotent. Pair with " +
		"`activeDeadlineSeconds` for a hard timeout.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "jobs", "reliability"},
	Scanner: "jobs.JobBackoffLimit",
}

func JobBackoffLimit(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, j := range g.ByType(k8scol.JobType) {
		bl := readInt32(j.Attributes["backoff_limit"])
		owner, _ := j.Attributes["owner_kind"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckJobBackoffLimit.ID,
			Severity: CheckJobBackoffLimit.Severity,
			Resource: j.Ref(),
			Tags:     CheckJobBackoffLimit.Tags,
		}
		// CronJob-owned Jobs inherit jobTemplate.spec.backoffLimit so
		// the policy lives on the parent. Skip transient cronjob jobs.
		if owner == "CronJob" {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("job %q: owned by CronJob (parent policy applies)", workloadDesc(j))
			findings = append(findings, f)
			continue
		}
		switch {
		case bl < 0:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("job %q: no backoffLimit set", workloadDesc(j))
		case bl > jobBackoffLimitCeiling:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("job %q: backoffLimit=%d exceeds ceiling of %d", workloadDesc(j), bl, jobBackoffLimitCeiling)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("job %q: backoffLimit=%d", workloadDesc(j), bl)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- CronJob concurrency policy --------------------------------

var CheckCronJobConcurrency = compliancekit.Check{
	ID:           "k8s-cronjob-concurrency",
	Title:        "CronJobs should not allow concurrent executions",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "jobs",
	ResourceType: k8scol.CronJobType,
	Description: "`concurrencyPolicy: Allow` (the default) lets a slow " +
		"run overlap with the next scheduled run, doubling cluster " +
		"load and frequently corrupting shared state — backup jobs, " +
		"cleanup tasks, and any cron that writes data should run one " +
		"at a time.",
	Remediation: "Set `concurrencyPolicy: Forbid` (skip overlap) or " +
		"`Replace` (kill the running instance and start the new one). " +
		"Allow is appropriate only for read-only, idempotent jobs.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "jobs", "cron"},
	Scanner: "jobs.CronJobConcurrency",
}

func CronJobConcurrency(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, cj := range g.ByType(k8scol.CronJobType) {
		policy, _ := cj.Attributes["concurrency_policy"].(string)
		if policy == "" {
			policy = "Allow"
		}
		f := compliancekit.Finding{
			CheckID:  CheckCronJobConcurrency.ID,
			Severity: CheckCronJobConcurrency.Severity,
			Resource: cj.Ref(),
			Tags:     CheckCronJobConcurrency.Tags,
		}
		if policy == "Forbid" || policy == "Replace" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("cronjob %q: concurrencyPolicy=%s", workloadDesc(cj), policy)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("cronjob %q: concurrencyPolicy=Allow permits overlapping runs", workloadDesc(cj))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- CronJob history limits ------------------------------------

var CheckCronJobHistoryLimit = compliancekit.Check{
	ID:           "k8s-cronjob-history-limit",
	Title:        "CronJobs should set successful and failed history limits",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "jobs",
	ResourceType: k8scol.CronJobType,
	Description: "Without `successfulJobsHistoryLimit` and " +
		"`failedJobsHistoryLimit`, the Job objects from every cronjob " +
		"run accumulate forever. After a year of hourly cronjobs that " +
		"is 8760 Job + Pod objects per cronjob — etcd bloat plus " +
		"slow `kubectl get jobs` plus pressure on the controller " +
		"manager.",
	Remediation: "Set `spec.successfulJobsHistoryLimit: 3` and " +
		"`spec.failedJobsHistoryLimit: 5` (or your operational " +
		"preference). The defaults of 3/1 are usually too small for " +
		"debugging.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "jobs", "cron", "etcd-hygiene"},
	Scanner: "jobs.CronJobHistoryLimit",
}

func CronJobHistoryLimit(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, cj := range g.ByType(k8scol.CronJobType) {
		success := readInt32(cj.Attributes["successful_jobs_history"])
		failed := readInt32(cj.Attributes["failed_jobs_history"])
		f := compliancekit.Finding{
			CheckID:  CheckCronJobHistoryLimit.ID,
			Severity: CheckCronJobHistoryLimit.Severity,
			Resource: cj.Ref(),
			Tags:     CheckCronJobHistoryLimit.Tags,
		}
		// -1 means the source value was unset; we want both set
		// explicitly so the policy is intentional.
		if success >= 0 && failed >= 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("cronjob %q: history limits set (%d/%d)", workloadDesc(cj), success, failed)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("cronjob %q: missing history limits (success=%d, failed=%d)", workloadDesc(cj), success, failed)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- CronJob starting deadline ---------------------------------

var CheckCronJobStartingDeadline = compliancekit.Check{
	ID:           "k8s-cronjob-starting-deadline",
	Title:        "CronJobs should set startingDeadlineSeconds",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "jobs",
	ResourceType: k8scol.CronJobType,
	Description: "Without `startingDeadlineSeconds`, the controller " +
		"keeps trying to start missed jobs after the scheduled time, " +
		"and once more than 100 misses accumulate it stops scheduling " +
		"the cronjob entirely. Setting an explicit deadline (e.g. 200 " +
		"seconds) lets old runs expire cleanly.",
	Remediation: "Set `spec.startingDeadlineSeconds` to a value greater " +
		"than your scheduling interval. 200 is a common starting point " +
		"for cronjobs that run more often than every 5 minutes.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "jobs", "cron"},
	Scanner: "jobs.CronJobStartingDeadline",
}

func CronJobStartingDeadline(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, cj := range g.ByType(k8scol.CronJobType) {
		deadline := readInt64(cj.Attributes["starting_deadline_seconds"])
		f := compliancekit.Finding{
			CheckID:  CheckCronJobStartingDeadline.ID,
			Severity: CheckCronJobStartingDeadline.Severity,
			Resource: cj.Ref(),
			Tags:     CheckCronJobStartingDeadline.Tags,
		}
		if deadline > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("cronjob %q: startingDeadlineSeconds=%d", workloadDesc(cj), deadline)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("cronjob %q: startingDeadlineSeconds unset (cronjob can stall after 100 missed runs)", workloadDesc(cj))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers + init --------------------------------------------

func init() {
	compliancekit.Register(CheckJobBackoffLimit, JobBackoffLimit)
	compliancekit.Register(CheckCronJobConcurrency, CronJobConcurrency)
	compliancekit.Register(CheckCronJobHistoryLimit, CronJobHistoryLimit)
	compliancekit.Register(CheckCronJobStartingDeadline, CronJobStartingDeadline)
}

// readInt32 accepts the various integer types that may end up in the
// attribute map after pointer dereferencing.
func readInt32(v any) int32 {
	switch x := v.(type) {
	case int32:
		return x
	case int:
		return int32(clampInt32(int64(x))) //nolint:gosec // clamped
	case int64:
		return int32(clampInt32(x)) //nolint:gosec // clamped
	}
	return -1
}

// clampInt32 keeps |x| within int32 range. Used by readInt32 to
// satisfy gosec G115 while accepting values that came from K8s API
// fields (which themselves were int32 pointers — never out of range
// in practice).
func clampInt32(x int64) int64 {
	const maxI32 = int64(^uint32(0) >> 1)
	if x > maxI32 {
		return maxI32
	}
	if x < -maxI32-1 {
		return -maxI32 - 1
	}
	return x
}

func readInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int32:
		return int64(x)
	case int:
		return int64(x)
	}
	return -1
}
