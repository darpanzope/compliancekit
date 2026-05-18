package aws

import (
	"context"
	"fmt"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckCloudTrailEnabled requires at least one trail to be actively
// logging. Anchored on the account resource (cross-trail aggregate
// check). CIS AWS Foundations 3.1.
var CheckCloudTrailEnabled = compliancekit.Check{
	ID:           "aws-cloudtrail-enabled",
	Title:        "At least one CloudTrail trail must be actively logging",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "cloudtrail",
	ResourceType: awscol.AccountType,
	Description: "CloudTrail is the API audit log for AWS. Without an " +
		"active trail, post-incident investigation cannot answer who " +
		"called what API, when, or from where. CIS AWS Foundations 3.1 " +
		"prescribes at least one trail covering every region, actively " +
		"logging.",
	Remediation: "Create a trail: 'aws cloudtrail create-trail --name " +
		"<name> --s3-bucket-name <bucket> --is-multi-region-trail " +
		"--enable-log-file-validation' then 'aws cloudtrail start-logging " +
		"--name <name>'. Ensure the S3 bucket has tight access controls.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"cloudtrail", "audit-logging"},
	Scanner: "cloudtrail.Enabled",
}

func CloudTrailEnabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	loggingTrails := 0
	for _, t := range g.ByType(awscol.CloudTrailType) {
		if logging, _ := t.Attributes["is_logging"].(bool); logging {
			loggingTrails++
		}
	}
	for _, acct := range g.ByType(awscol.AccountType) {
		f := compliancekit.Finding{
			CheckID:  CheckCloudTrailEnabled.ID,
			Severity: CheckCloudTrailEnabled.Severity,
			Resource: acct.Ref(),
			Tags:     CheckCloudTrailEnabled.Tags,
		}
		if loggingTrails > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: %d trails actively logging", acct.Name, loggingTrails)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: no trails actively logging", acct.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckCloudTrailMultiRegion requires at least one multi-region
// trail. CIS 3.1.
var CheckCloudTrailMultiRegion = compliancekit.Check{
	ID:           "aws-cloudtrail-multi-region",
	Title:        "At least one CloudTrail trail must be multi-region",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "cloudtrail",
	ResourceType: awscol.AccountType,
	Description: "A single-region trail misses API calls in every other " +
		"region the account uses, including the global IAM, S3, and " +
		"CloudFront APIs. A multi-region trail captures the entire account. " +
		"CIS AWS Foundations 3.1 prescribes at least one multi-region trail.",
	Remediation: "Convert: 'aws cloudtrail update-trail --name <name> " +
		"--is-multi-region-trail'. If you have multiple single-region trails, " +
		"consolidating to one multi-region trail reduces cost and improves " +
		"forensic coverage.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"cloudtrail", "audit-logging", "multi-region"},
	Scanner: "cloudtrail.MultiRegion",
}

func CloudTrailMultiRegion(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	multi := 0
	for _, t := range g.ByType(awscol.CloudTrailType) {
		logging, _ := t.Attributes["is_logging"].(bool)
		mr, _ := t.Attributes["is_multi_region"].(bool)
		if logging && mr {
			multi++
		}
	}
	for _, acct := range g.ByType(awscol.AccountType) {
		f := compliancekit.Finding{
			CheckID:  CheckCloudTrailMultiRegion.ID,
			Severity: CheckCloudTrailMultiRegion.Severity,
			Resource: acct.Ref(),
			Tags:     CheckCloudTrailMultiRegion.Tags,
		}
		if multi > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: %d multi-region trails logging", acct.Name, multi)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: no multi-region trails actively logging", acct.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckCloudTrailLogFileValidation requires every trail to have
// log-file integrity validation. CIS 3.2.
var CheckCloudTrailLogFileValidation = compliancekit.Check{
	ID:           "aws-cloudtrail-log-file-validation",
	Title:        "CloudTrail trails must have log file validation enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "cloudtrail",
	ResourceType: awscol.CloudTrailType,
	Description: "Log file validation publishes a SHA-256 digest of every " +
		"hour's log batch to a separate file in the same S3 bucket. The " +
		"digest is signed with an account-specific private key whose " +
		"public counterpart is stored by AWS. Without it, post-tamper " +
		"detection of log files is not possible. CIS AWS Foundations 3.2.",
	Remediation: "Enable: 'aws cloudtrail update-trail --name <name> " +
		"--enable-log-file-validation'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"cloudtrail", "integrity"},
	Scanner: "cloudtrail.LogFileValidation",
}

func CloudTrailLogFileValidation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, t := range g.ByType(awscol.CloudTrailType) {
		v, _ := t.Attributes["log_file_validation_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckCloudTrailLogFileValidation.ID,
			Severity: CheckCloudTrailLogFileValidation.Severity,
			Resource: t.Ref(),
			Tags:     CheckCloudTrailLogFileValidation.Tags,
		}
		if v {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("trail %q: log file validation enabled", t.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("trail %q: log file validation disabled", t.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckCloudTrailEnabled, CloudTrailEnabled)
	compliancekit.Register(CheckCloudTrailMultiRegion, CloudTrailMultiRegion)
	compliancekit.Register(CheckCloudTrailLogFileValidation, CloudTrailLogFileValidation)
}
