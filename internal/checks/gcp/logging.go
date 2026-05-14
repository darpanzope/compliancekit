package gcp

import (
	"context"
	"fmt"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// minLogRetentionDays is the threshold used by CheckLogBucketRetention.
// Many regulated workloads (SOC 2, ISO 27001 with 12-month audit
// windows, PCI-DSS) require at least one year of audit-log retention.
const minLogRetentionDays = 365

// longTermSinkDestinations is the set of destination types that
// preserve log entries beyond the Cloud Logging retention window.
// GCS, BigQuery, and Pub-Sub all qualify; a sink that writes back
// into another Cloud Logging bucket does not (still bound by that
// bucket's retention).
var longTermSinkDestinations = map[string]bool{
	"gcs":      true,
	"bigquery": true,
	"pubsub":   true,
}

// CheckLoggingSinkExists requires that each scanned project has at
// least one enabled, non-empty-filter (or catch-all) sink that
// exports log entries to a long-term destination. CIS GCP
// Foundations 2.2.
var CheckLoggingSinkExists = core.Check{
	ID:           "gcp-logging-sink-exists",
	Title:        "Each project must export logs to a long-term sink",
	Severity:     core.SeverityHigh,
	Provider:     "gcp",
	Service:      "logging",
	ResourceType: gcpcol.ProjectType,
	Description: "Cloud Logging buckets default to 30-day retention, which " +
		"isn't enough for incident response or compliance evidence over an " +
		"audit window. A sink exporting to GCS / BigQuery / Pub-Sub gives the " +
		"operator a durable, queryable archive that survives bucket TTL. CIS " +
		"GCP Foundations 2.2.",
	Remediation: "Create a project-level sink with no filter (catches " +
		"everything): 'gcloud logging sinks create all-to-gcs " +
		"storage.googleapis.com/<bucket> --project=<project>'. Then grant " +
		"the sink's writer_identity roles/storage.objectCreator on the " +
		"destination bucket.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.2", "8.10"},
	},
	Tags:    []string{"logging", "audit-trail", "retention"},
	Scanner: "logging.SinkExists",
}

func LoggingSinkExists(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	// Group sinks by project so the check renders one finding per
	// project regardless of how many sinks exist.
	sinksByProject := map[string][]core.Resource{}
	for _, s := range g.ByType(gcpcol.LogSinkType) {
		projectID, _ := s.Attributes["account_id"].(string)
		sinksByProject[projectID] = append(sinksByProject[projectID], s)
	}

	for _, proj := range g.ByType(gcpcol.ProjectType) {
		projectID, _ := proj.Attributes["project_id"].(string)
		f := core.Finding{
			CheckID:  CheckLoggingSinkExists.ID,
			Severity: CheckLoggingSinkExists.Severity,
			Resource: proj.Ref(),
			Tags:     CheckLoggingSinkExists.Tags,
		}
		var qualifying []string
		for _, s := range sinksByProject[projectID] {
			disabled, _ := s.Attributes["disabled"].(bool)
			if disabled {
				continue
			}
			destType, _ := s.Attributes["destination_type"].(string)
			if longTermSinkDestinations[destType] {
				qualifying = append(qualifying, s.Name)
			}
		}
		if len(qualifying) > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("project %q: %d long-term sink(s): %v", projectID, len(qualifying), qualifying)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: no enabled sink exports to GCS/BigQuery/Pub-Sub", projectID)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckLogBucketRetention requires the _Default log bucket retain
// entries for at least minLogRetentionDays. Other (user-created)
// buckets are also checked; _Required is skipped because its
// retention is fixed at 400 days by Google and cannot be changed.
var CheckLogBucketRetention = core.Check{
	ID:           "gcp-logging-bucket-retention",
	Title:        "Cloud Logging buckets must retain entries for at least 365 days",
	Severity:     core.SeverityMedium,
	Provider:     "gcp",
	Service:      "logging",
	ResourceType: gcpcol.LogBucketType,
	Description: "Most compliance frameworks expect at least 12 months of " +
		"audit-log retention to cover an annual audit window. The Cloud " +
		"Logging default is 30 days, which is well short. Lengthening " +
		"retention on the _Default bucket (or routing to a longer-retention " +
		"sink) is the cheapest way to clear the bar.",
	Remediation: "'gcloud logging buckets update _Default --location=global " +
		"--retention-days=365 --project=<project>'. Combine with a sink to " +
		"GCS for retention beyond 3650 days (the bucket maximum).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.10"},
	},
	Tags:    []string{"logging", "retention", "audit-trail"},
	Scanner: "logging.BucketRetention",
}

func LogBucketRetention(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(gcpcol.LogBucketType) {
		// _Required is Google-managed (fixed 400-day retention).
		// Skip rather than emit a misleading pass/fail.
		if b.Name == "_Required" {
			continue
		}
		days, _ := b.Attributes["retention_days"].(int)
		f := core.Finding{
			CheckID:  CheckLogBucketRetention.ID,
			Severity: CheckLogBucketRetention.Severity,
			Resource: b.Ref(),
			Tags:     CheckLogBucketRetention.Tags,
		}
		if days >= minLogRetentionDays {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: retention %dd", b.Name, days)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: retention %dd (want >= %dd)", b.Name, days, minLogRetentionDays)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckLoggingSinkExists, LoggingSinkExists)
	core.Register(CheckLogBucketRetention, LogBucketRetention)
}
