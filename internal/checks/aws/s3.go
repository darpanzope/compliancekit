package aws

import (
	"context"
	"fmt"
	"strings"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ========================================================================
// S3 checks (anchored on aws.s3.bucket resources)
// ========================================================================

// CheckS3PublicAccessBlock requires every bucket to have the S3
// Public Access Block fully enabled (all four settings true). CIS
// AWS Foundations Benchmark 2.1.1 prescribes this as the universal
// safeguard against the "we accidentally made a bucket public" class
// of incident.
var CheckS3PublicAccessBlock = core.Check{
	ID:           "aws-s3-public-access-block",
	Title:        "S3 buckets must have Block Public Access fully enabled",
	Severity:     core.SeverityCritical,
	Provider:     "aws",
	Service:      "s3",
	ResourceType: awscol.S3BucketType,
	Description: "S3 Public Access Block is the account-and-bucket-level " +
		"safety net against accidental data exposure: even if a bucket policy " +
		"or ACL tries to grant public access, PAB overrides. All four flags " +
		"(block_public_acls, ignore_public_acls, block_public_policy, " +
		"restrict_public_buckets) must be true. CIS AWS Foundations 2.1.1.",
	Remediation: "Enable all four settings: 'aws s3api put-public-access-block " +
		"--bucket <name> --public-access-block-configuration " +
		"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true," +
		"RestrictPublicBuckets=true'. Consider account-level PAB " +
		"('aws s3control put-public-access-block --account-id ...') for " +
		"defense-in-depth.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.8.20"},
		"cis-v8":   {"3.3", "3.11"},
	},
	Tags:    []string{"s3", "data-exposure", "public-access"},
	Scanner: "s3.PublicAccessBlock",
}

func S3PublicAccessBlock(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(awscol.S3BucketType) {
		pab, _ := b.Attributes["public_access_block"].(map[string]any)
		f := core.Finding{
			CheckID:  CheckS3PublicAccessBlock.ID,
			Severity: CheckS3PublicAccessBlock.Severity,
			Resource: b.Ref(),
			Tags:     CheckS3PublicAccessBlock.Tags,
		}
		if pab == nil {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("bucket %q: public_access_block attribute missing", b.Name)
			findings = append(findings, f)
			continue
		}
		configured, _ := pab["configured"].(bool)
		if !configured {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: no Public Access Block configured", b.Name)
			findings = append(findings, f)
			continue
		}
		missing := []string{}
		for _, k := range []string{
			"block_public_acls", "ignore_public_acls",
			"block_public_policy", "restrict_public_buckets",
		} {
			if v, _ := pab[k].(bool); !v {
				missing = append(missing, k)
			}
		}
		if len(missing) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: all PAB flags enabled", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: PAB flags disabled: %s",
				b.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckS3DefaultEncryption requires server-side default encryption.
// CIS 2.1.2. High.
var CheckS3DefaultEncryption = core.Check{
	ID:           "aws-s3-default-encryption",
	Title:        "S3 buckets must have default server-side encryption",
	Severity:     core.SeverityHigh,
	Provider:     "aws",
	Service:      "s3",
	ResourceType: awscol.S3BucketType,
	Description: "Default encryption ensures every object written to the " +
		"bucket is encrypted at rest without requiring the caller to set the " +
		"header. SSE-S3 (AES256) is the minimum; SSE-KMS gives per-key audit " +
		"trails for sensitive data. AWS has enabled SSE-S3 by default on new " +
		"buckets since January 2023 but pre-existing buckets retain their " +
		"original setting. CIS AWS Foundations 2.1.2.",
	Remediation: "Enable default encryption: 'aws s3api put-bucket-encryption " +
		"--bucket <name> --server-side-encryption-configuration '" +
		"\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'. " +
		"Use SSEAlgorithm=aws:kms for KMS-managed keys.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"s3", "encryption", "data-at-rest"},
	Scanner: "s3.DefaultEncryption",
}

func S3DefaultEncryption(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(awscol.S3BucketType) {
		configured, _ := b.Attributes["default_encryption_configured"].(bool)
		algorithm, _ := b.Attributes["default_encryption_algorithm"].(string)
		f := core.Finding{
			CheckID:  CheckS3DefaultEncryption.ID,
			Severity: CheckS3DefaultEncryption.Severity,
			Resource: b.Ref(),
			Tags:     CheckS3DefaultEncryption.Tags,
		}
		if configured {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: default encryption %s", b.Name, algorithm)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: no default encryption configured", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckS3Versioning requires versioning to be Enabled.
// Versioning gives ransomware / accidental-delete recovery and is
// the documented prerequisite for several other controls (MFA delete,
// object lock).
var CheckS3Versioning = core.Check{
	ID:           "aws-s3-versioning",
	Title:        "S3 buckets must have versioning enabled",
	Severity:     core.SeverityMedium,
	Provider:     "aws",
	Service:      "s3",
	ResourceType: awscol.S3BucketType,
	Description: "Bucket versioning preserves prior versions of every " +
		"object, recovering from ransomware encryption-in-place, accidental " +
		"deletion, and silent corruption. Versioning is a prerequisite for " +
		"S3 Object Lock and MFA Delete -- enabling it now is the minimum " +
		"viable backup story for S3.",
	Remediation: "Enable versioning: 'aws s3api put-bucket-versioning " +
		"--bucket <name> --versioning-configuration Status=Enabled'. " +
		"Consider lifecycle rules to expire old non-current versions if " +
		"storage cost is a concern.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "A1.2"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"s3", "backup", "recovery"},
	Scanner: "s3.Versioning",
}

func S3Versioning(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(awscol.S3BucketType) {
		status, _ := b.Attributes["versioning_status"].(string)
		f := core.Finding{
			CheckID:  CheckS3Versioning.ID,
			Severity: CheckS3Versioning.Severity,
			Resource: b.Ref(),
			Tags:     CheckS3Versioning.Tags,
		}
		if status == "Enabled" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: versioning enabled", b.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: versioning %q (want Enabled)", b.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckS3Logging requires server-access logging.
// CIS 3.6 (formerly 2.6).
var CheckS3Logging = core.Check{
	ID:           "aws-s3-logging",
	Title:        "S3 buckets must have server access logging enabled",
	Severity:     core.SeverityLow,
	Provider:     "aws",
	Service:      "s3",
	ResourceType: awscol.S3BucketType,
	Description: "Server access logs are the forensic trail when a bucket " +
		"is the source of a security incident. Without them, 'who accessed " +
		"this bucket at this timestamp' is unanswerable. CIS AWS Foundations " +
		"3.6 (formerly 2.6 in v1.x of the benchmark).",
	Remediation: "Enable logging to a dedicated log-aggregation bucket: " +
		"'aws s3api put-bucket-logging --bucket <name> " +
		"--bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\"," +
		"\"TargetPrefix\":\"<prefix>/\"}}'. The target bucket should NOT be the " +
		"source bucket (creates a logging loop).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"s3", "audit-logging", "forensics"},
	Scanner: "s3.Logging",
}

func S3Logging(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(awscol.S3BucketType) {
		enabled, _ := b.Attributes["logging_enabled"].(bool)
		target, _ := b.Attributes["logging_target_bucket"].(string)
		f := core.Finding{
			CheckID:  CheckS3Logging.ID,
			Severity: CheckS3Logging.Severity,
			Resource: b.Ref(),
			Tags:     CheckS3Logging.Tags,
		}
		switch {
		case !enabled:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: server access logging disabled", b.Name)
		case target == b.Name:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: logging target is the same bucket (loop)", b.Name)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: logging to %q", b.Name, target)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckS3NoPublicACLs forbids ACLs that grant AllUsers or
// AuthenticatedUsers principal groups. The PAB check covers the
// account-level safety net; this catches buckets where PAB is off
// (legacy, intentional) and an ACL has slipped public.
var CheckS3NoPublicACLs = core.Check{
	ID:           "aws-s3-no-public-acls",
	Title:        "S3 buckets must not have public ACLs",
	Severity:     core.SeverityHigh,
	Provider:     "aws",
	Service:      "s3",
	ResourceType: awscol.S3BucketType,
	Description: "S3 ACLs that grant the AllUsers or AuthenticatedUsers " +
		"groups make a bucket publicly readable or writable. Combined with " +
		"a misconfigured Public Access Block (PAB), this is the most common " +
		"path to a public bucket. PAB is the safety net; this check catches " +
		"buckets where PAB is off and an ACL has slipped public.",
	Remediation: "Remove the public grant: 'aws s3api put-bucket-acl " +
		"--bucket <name> --acl private'. If specific objects need to be " +
		"public, prefer a least-privilege bucket policy over an ACL.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.8.20"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"s3", "data-exposure", "acl"},
	Scanner: "s3.NoPublicACLs",
}

func S3NoPublicACLs(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, b := range g.ByType(awscol.S3BucketType) {
		public, _ := b.Attributes["public_acls"].(bool)
		f := core.Finding{
			CheckID:  CheckS3NoPublicACLs.ID,
			Severity: CheckS3NoPublicACLs.Severity,
			Resource: b.Ref(),
			Tags:     CheckS3NoPublicACLs.Tags,
		}
		if public {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("bucket %q: ACL grants public (AllUsers or AuthenticatedUsers)", b.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("bucket %q: no public ACL grants", b.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckS3PublicAccessBlock, S3PublicAccessBlock)
	core.Register(CheckS3DefaultEncryption, S3DefaultEncryption)
	core.Register(CheckS3Versioning, S3Versioning)
	core.Register(CheckS3Logging, S3Logging)
	core.Register(CheckS3NoPublicACLs, S3NoPublicACLs)
}
