package gcp

import (
	"context"
	"fmt"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckGCSUniformAccess requires Uniform Bucket-Level Access (UBLA)
// on every bucket. CIS GCP 5.2.
var CheckGCSUniformAccess = compliancekit.Check{
	ID:           "gcp-storage-uniform-bucket-level-access",
	Title:        "GCS buckets must use Uniform Bucket-Level Access",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "gcp",
	Service:      "storage",
	ResourceType: gcpcol.GCSBucketType,
	Description: "Uniform Bucket-Level Access disables per-object ACLs and " +
		"forces all access through IAM bindings at the bucket level. ACLs " +
		"are the legacy path that produces public buckets via accidental " +
		"`allUsers` grants; UBLA eliminates that surface entirely. CIS GCP " +
		"Foundations 5.2.",
	Remediation: "'gsutil uniformbucketlevelaccess set on gs://<bucket>'. " +
		"Once UBLA is on, manage permissions only via IAM at the bucket or " +
		"project level.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.8.20"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"storage", "data-exposure", "iam"},
	Scanner: "storage.UniformAccess",
}

func GCSUniformAccess(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, b := range g.ByType(gcpcol.GCSBucketType) {
		on, _ := b.Attributes["uniform_bucket_level_access"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckGCSUniformAccess.ID,
			Severity: CheckGCSUniformAccess.Severity,
			Resource: b.Ref(),
			Tags:     CheckGCSUniformAccess.Tags,
		}
		if on {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("bucket %q: UBLA enabled", b.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("bucket %q: UBLA disabled (ACLs still active)", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckGCSPAP requires Public Access Prevention = enforced.
// CIS GCP 5.1.
var CheckGCSPAP = compliancekit.Check{
	ID:           "gcp-storage-public-access-prevention",
	Title:        "GCS buckets must have Public Access Prevention enforced",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "gcp",
	Service:      "storage",
	ResourceType: gcpcol.GCSBucketType,
	Description: "Public Access Prevention is the bucket- or org-level " +
		"switch that overrides any IAM binding or ACL granting public " +
		"access. With PAP=enforced, `allUsers` and `allAuthenticatedUsers` " +
		"grants are rejected outright at the API. Combined with UBLA, this " +
		"is the strongest defense against accidental public-bucket " +
		"incidents. CIS GCP Foundations 5.1.",
	Remediation: "'gsutil pap set enforced gs://<bucket>'. Better still, " +
		"set an organization policy " +
		"(constraints/storage.publicAccessPrevention) so new buckets " +
		"inherit PAP automatically.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.8.20"},
		"cis-v8":   {"3.3", "3.11"},
	},
	Tags:    []string{"storage", "data-exposure", "public-access"},
	Scanner: "storage.PAP",
}

func GCSPAP(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, b := range g.ByType(gcpcol.GCSBucketType) {
		pap, _ := b.Attributes["public_access_prevention"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckGCSPAP.ID,
			Severity: CheckGCSPAP.Severity,
			Resource: b.Ref(),
			Tags:     CheckGCSPAP.Tags,
		}
		if pap == "enforced" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("bucket %q: public access prevention enforced", b.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("bucket %q: public_access_prevention=%q (want enforced)", b.Name, pap)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckGCSVersioning requires bucket versioning. Recovery from
// ransomware / accidental delete.
var CheckGCSVersioning = compliancekit.Check{
	ID:           "gcp-storage-versioning",
	Title:        "GCS buckets must have versioning enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "gcp",
	Service:      "storage",
	ResourceType: gcpcol.GCSBucketType,
	Description: "Object versioning preserves previous versions of every " +
		"object, giving point-in-time recovery from accidental delete and " +
		"ransomware encryption-in-place. The CIS GCP Foundations Benchmark " +
		"does not pin versioning specifically, but every reasonable " +
		"production-readiness checklist does.",
	Remediation: "'gsutil versioning set on gs://<bucket>'. Pair with a " +
		"lifecycle rule to expire old non-current versions if storage cost " +
		"is a concern.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "A1.2"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"storage", "backup", "recovery"},
	Scanner: "storage.Versioning",
}

func GCSVersioning(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, b := range g.ByType(gcpcol.GCSBucketType) {
		on, _ := b.Attributes["versioning_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckGCSVersioning.ID,
			Severity: CheckGCSVersioning.Severity,
			Resource: b.Ref(),
			Tags:     CheckGCSVersioning.Tags,
		}
		if on {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("bucket %q: versioning enabled", b.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("bucket %q: versioning disabled", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckGCSLogging requires server-access logging.
var CheckGCSLogging = compliancekit.Check{
	ID:           "gcp-storage-logging",
	Title:        "GCS buckets must have access logging configured",
	Severity:     compliancekit.SeverityLow,
	Provider:     "gcp",
	Service:      "storage",
	ResourceType: gcpcol.GCSBucketType,
	Description: "GCS access logs are the forensic trail when a bucket is " +
		"the source of a security incident. Without them, 'who accessed " +
		"this object at this timestamp' is unanswerable. Cloud Audit Logs " +
		"cover the management plane; bucket access logs cover the data " +
		"plane.",
	Remediation: "Enable access logging to a dedicated log-aggregation " +
		"bucket: 'gsutil logging set on -b gs://<log-bucket> " +
		"-o AccessLog gs://<bucket>'. The log bucket must not be the source " +
		"bucket (would create a logging loop).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"storage", "audit-logging"},
	Scanner: "storage.Logging",
}

func GCSLogging(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, b := range g.ByType(gcpcol.GCSBucketType) {
		enabled, _ := b.Attributes["logging_enabled"].(bool)
		target, _ := b.Attributes["logging_target_bucket"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckGCSLogging.ID,
			Severity: CheckGCSLogging.Severity,
			Resource: b.Ref(),
			Tags:     CheckGCSLogging.Tags,
		}
		switch {
		case !enabled:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("bucket %q: access logging disabled", b.Name)
		case target == b.Name:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("bucket %q: logging target is the same bucket (loop)", b.Name)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("bucket %q: logging to %q", b.Name, target)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckGCSUniformAccess, GCSUniformAccess)
	compliancekit.Register(CheckGCSPAP, GCSPAP)
	compliancekit.Register(CheckGCSVersioning, GCSVersioning)
	compliancekit.Register(CheckGCSLogging, GCSLogging)
}
