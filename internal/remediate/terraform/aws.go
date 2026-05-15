package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

func init() {
	// S3 ---------------------------------------------------------------
	register("tf-aws-s3-public-access-block",
		[]string{"aws-s3-public-access-block"},
		renderAWSS3PublicAccessBlock)
	register("tf-aws-s3-default-encryption",
		[]string{"aws-s3-default-encryption"},
		renderAWSS3DefaultEncryption)
	register("tf-aws-s3-versioning",
		[]string{"aws-s3-versioning"},
		renderAWSS3Versioning)
	register("tf-aws-s3-logging",
		[]string{"aws-s3-logging"},
		renderAWSS3Logging)
	register("tf-aws-s3-no-public-acls",
		[]string{"aws-s3-no-public-acls"},
		renderAWSS3NoPublicACLs)

	// IAM --------------------------------------------------------------
	register("tf-aws-iam-password-policy",
		[]string{"aws-iam-password-policy"},
		renderAWSIAMPasswordPolicy)
	register("tf-aws-iam-root-manual",
		[]string{"aws-iam-root-mfa", "aws-iam-root-access-key"},
		renderAWSIAMRootManual)

	// CloudTrail -------------------------------------------------------
	register("tf-aws-cloudtrail",
		[]string{
			"aws-cloudtrail-enabled",
			"aws-cloudtrail-multi-region",
			"aws-cloudtrail-log-file-validation",
		},
		renderAWSCloudTrail)

	// EC2 --------------------------------------------------------------
	register("tf-aws-ec2-ebs-encryption-by-default",
		[]string{"aws-ec2-ebs-encrypted"},
		renderAWSEC2EBSEncryptionDefault)
	register("tf-aws-ec2-imdsv2",
		[]string{"aws-ec2-imdsv2-required"},
		renderAWSEC2IMDSv2)

	// RDS --------------------------------------------------------------
	register("tf-aws-rds-deletion-protection",
		[]string{"aws-rds-deletion-protection"},
		renderAWSRDSDeletionProtection)
	register("tf-aws-rds-backup-retention",
		[]string{"aws-rds-backup-retention"},
		renderAWSRDSBackupRetention)
	register("tf-aws-rds-not-publicly-accessible",
		[]string{"aws-rds-not-publicly-accessible"},
		renderAWSRDSNotPublic)
	register("tf-aws-rds-encrypted-manual",
		[]string{"aws-rds-encrypted"},
		renderAWSRDSEncryptedManual)

	// KMS --------------------------------------------------------------
	register("tf-aws-kms-cmk-rotation",
		[]string{"aws-kms-cmk-rotation"},
		renderAWSKMSRotation)

	// GuardDuty + Config ----------------------------------------------
	register("tf-aws-guardduty-enabled",
		[]string{"aws-guardduty-enabled"},
		renderAWSGuardDuty)
	register("tf-aws-config-recorder-on",
		[]string{"aws-config-recorder-on", "aws-config-delivery-channel"},
		renderAWSConfig)
}

// --- S3 ----------------------------------------------------------------

func renderAWSS3PublicAccessBlock(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_s3_bucket_public_access_block", tfIdent(bucket))
	b.Attr("bucket", bucket)
	b.Attr("block_public_acls", true)
	b.Attr("block_public_policy", true)
	b.Attr("ignore_public_acls", true)
	b.Attr("restrict_public_buckets", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws s3api get-public-access-block --bucket %s", render.ShellQuote(bucket)),
		Notes:      "Blocks new and existing public ACLs and policies on the bucket. Has no effect on already-private buckets and does not break legitimate cross-account access via signed URLs.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
	}, nil
}

func renderAWSS3DefaultEncryption(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_s3_bucket_server_side_encryption_configuration", tfIdent(bucket))
	b.Attr("bucket", bucket)
	rule := b.SubBlock("rule")
	apply := rule.SubBlock("apply_server_side_encryption_by_default")
	apply.Attr("sse_algorithm", "AES256")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws s3api get-bucket-encryption --bucket %s", render.ShellQuote(bucket)),
		Notes:      "Enables AES-256 SSE-S3 by default for new objects. Existing objects are not re-encrypted; re-upload or run an inventory + batch copy if backfill is required.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
		},
	}, nil
}

func renderAWSS3Versioning(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_s3_bucket_versioning", tfIdent(bucket))
	b.Attr("bucket", bucket)
	v := b.SubBlock("versioning_configuration")
	v.Attr("status", "Enabled")
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws s3api get-bucket-versioning --bucket %s", render.ShellQuote(bucket)),
		Notes:      "Enabling versioning protects against accidental overwrite and ransomware. Plan a lifecycle policy to expire noncurrent versions — versioning charges storage for every revision.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
		},
	}, nil
}

func renderAWSS3Logging(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_s3_bucket_logging", tfIdent(bucket))
	b.Attr("bucket", bucket)
	b.RawAttr("target_bucket", "aws_s3_bucket.access_logs.id")
	b.Attr("target_prefix", fmt.Sprintf("s3/%s/", bucket))
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		Notes:      "Requires a separate aws_s3_bucket.access_logs target bucket with permission to receive logs (see AWS docs § 'Granting access to S3 Log Delivery group'). Review the target before applying.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html",
		},
	}, nil
}

func renderAWSS3NoPublicACLs(f core.Finding) (remediate.Snippet, error) {
	bucket := f.Resource.Name
	if bucket == "" {
		bucket = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_s3_bucket_acl", tfIdent(bucket))
	b.Attr("bucket", bucket)
	b.Attr("acl", "private")
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws s3api get-bucket-acl --bucket %s", render.ShellQuote(bucket)),
		Notes:      "Sets the bucket ACL to private. If legitimate cross-account access uses ACLs (rare), switch to a bucket policy with explicit principal grants instead — flipping ACL to private would break those grants.",
	}, nil
}

// --- IAM ---------------------------------------------------------------

func renderAWSIAMPasswordPolicy(_ core.Finding) (remediate.Snippet, error) {
	b := render.NewHCLBlock("resource", "aws_iam_account_password_policy", "fix")
	b.Attr("minimum_password_length", 14)
	b.Attr("require_lowercase_characters", true)
	b.Attr("require_uppercase_characters", true)
	b.Attr("require_numbers", true)
	b.Attr("require_symbols", true)
	b.Attr("allow_users_to_change_password", true)
	b.Attr("max_password_age", 90)
	b.Attr("password_reuse_prevention", 24)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  "aws iam get-account-password-policy",
		Notes:      "Aligns with CIS AWS Foundations 1.8-1.14. Users whose existing passwords violate the new policy will be forced to change on next sign-in.",
		Refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
		},
	}, nil
}

func renderAWSIAMRootManual(f core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation required — see Notes.\n",
		Notes:      fmt.Sprintf("Finding %q affects the AWS root user. Root credentials cannot be managed via Terraform. Steps: 1) sign in as the AWS root user; 2) enable hardware MFA in the account security credentials page; 3) delete any active root access keys. Track via the POA&M emitted alongside this snippet.", f.CheckID),
		Refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
		},
	}, nil
}

// --- CloudTrail --------------------------------------------------------

func renderAWSCloudTrail(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "audit"
	}
	b := render.NewHCLBlock("resource", "aws_cloudtrail", tfIdent(name))
	b.Attr("name", name)
	b.RawAttr("s3_bucket_name", "aws_s3_bucket.cloudtrail_logs.id")
	b.Attr("is_multi_region_trail", true)
	b.Attr("include_global_service_events", true)
	b.Attr("enable_log_file_validation", true)
	b.Attr("enable_logging", true)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws cloudtrail describe-trails --trail-name-list %s", render.ShellQuote(name)),
		Notes:      "Single resource fixes all three CloudTrail findings (enabled / multi-region / log-file-validation). Requires aws_s3_bucket.cloudtrail_logs with the CloudTrail service principal in its bucket policy — see linked AWS guide.",
		Refs: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
		},
	}, nil
}

// --- EC2 ---------------------------------------------------------------

func renderAWSEC2EBSEncryptionDefault(_ core.Finding) (remediate.Snippet, error) {
	b := render.NewHCLBlock("resource", "aws_ebs_encryption_by_default", "fix")
	b.Attr("enabled", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  "aws ec2 get-ebs-encryption-by-default",
		Notes:      "Account-level + region-level default: every new EBS volume in this region is encrypted with the default AWS-managed KMS key. Does not retroactively encrypt existing volumes — see aws_kms_key + aws_ebs_default_kms_key for CMK control.",
		Refs: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default",
		},
	}, nil
}

func renderAWSEC2IMDSv2(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_instance", tfIdent(name))
	b.Attr("# NOTE: append the following metadata_options block to your existing aws_instance", "")
	mo := b.SubBlock("metadata_options")
	mo.Attr("http_tokens", "required")
	mo.Attr("http_endpoint", "enabled")
	mo.Attr("http_put_response_hop_limit", 1)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws ec2 describe-instances --instance-ids %s --query 'Reservations[].Instances[].MetadataOptions'", render.ShellQuote(name)),
		Notes:      "Forces IMDSv2 (token-required). Old SDKs lacking IMDSv2 support will fail; verify your AMI and userdata use a recent AWS SDK before applying. Hop limit 1 prevents container escape via IMDS proxying.",
		Refs: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html",
		},
	}, nil
}

// --- RDS ---------------------------------------------------------------

func renderAWSRDSDeletionProtection(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_db_instance", tfIdent(name))
	b.Attr("# NOTE: set deletion_protection on your existing aws_db_instance", "")
	b.Attr("identifier", name)
	b.Attr("deletion_protection", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].DeletionProtection'", render.ShellQuote(name)),
		Notes:      "Prevents accidental `terraform destroy` from removing the database. Doesn't prevent legitimate teardown — drop deletion_protection back to false when you intend to delete.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeletionProtection",
		},
	}, nil
}

func renderAWSRDSBackupRetention(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_db_instance", tfIdent(name))
	b.Attr("# NOTE: set backup_retention_period on your existing aws_db_instance", "")
	b.Attr("identifier", name)
	b.Attr("backup_retention_period", 7)
	b.Attr("backup_window", "03:00-04:00")
	b.Attr("copy_tags_to_snapshot", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].BackupRetentionPeriod'", render.ShellQuote(name)),
		Notes:      "7-day retention is the CIS minimum; raise to 35 for production-grade RTO/RPO. Backup window is in UTC.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
		},
	}, nil
}

func renderAWSRDSNotPublic(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_db_instance", tfIdent(name))
	b.Attr("# NOTE: flip publicly_accessible to false on your existing aws_db_instance", "")
	b.Attr("identifier", name)
	b.Attr("publicly_accessible", false)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].PubliclyAccessible'", render.ShellQuote(name)),
		Notes:      "Removes the public DNS endpoint. Applications connecting from outside the VPC will break — verify all consumers either run inside the VPC or reach RDS via VPC peering / Transit Gateway before applying.",
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDSSecurityGroups.html",
		},
	}, nil
}

func renderAWSRDSEncryptedManual(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation required — encryption-at-rest cannot be enabled in-place.\n",
		Notes: fmt.Sprintf(
			"Enabling RDS storage encryption on existing instance %q requires: 1) snapshot the instance; 2) copy the snapshot with --kms-key-id and encrypted=true; 3) restore as a new instance; 4) cut traffic over; 5) decommission the original. Track via POA&M.",
			name),
		Refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling",
		},
	}, nil
}

// --- KMS ---------------------------------------------------------------

func renderAWSKMSRotation(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = f.Resource.ID
	}
	b := render.NewHCLBlock("resource", "aws_kms_key", tfIdent(name))
	b.Attr("# NOTE: enable rotation on the existing aws_kms_key", "")
	b.Attr("description", fmt.Sprintf("rotation-enabled for key %s", name))
	b.Attr("enable_key_rotation", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  fmt.Sprintf("aws kms get-key-rotation-status --key-id %s", render.ShellQuote(name)),
		Notes:      "Annual automatic rotation of the KMS-CMK key material. Transparent to consumers — old data remains decryptable with the new key version. Asymmetric keys do not support rotation; leave as-is.",
		Refs: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		},
	}, nil
}

// --- GuardDuty + Config -----------------------------------------------

func renderAWSGuardDuty(_ core.Finding) (remediate.Snippet, error) {
	b := render.NewHCLBlock("resource", "aws_guardduty_detector", "fix")
	b.Attr("enable", true)
	b.Attr("finding_publishing_frequency", "FIFTEEN_MINUTES")
	dpf := b.SubBlock("datasources")
	s3 := dpf.SubBlock("s3_logs")
	s3.Attr("enable", true)
	k8s := dpf.SubBlock("kubernetes")
	auditLogs := k8s.SubBlock("audit_logs")
	auditLogs.Attr("enable", true)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    b.String(),
		VerifyCmd:  "aws guardduty list-detectors",
		Notes:      "Enables GuardDuty in the current region with S3 + EKS audit-log data sources. ~$5-30/month per region for typical accounts. Deploy via Terraform aws.regional providers for full multi-region coverage.",
		Refs: []string{
			"https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html",
		},
	}, nil
}

func renderAWSConfig(_ core.Finding) (remediate.Snippet, error) {
	rec := render.NewHCLBlock("resource", "aws_config_configuration_recorder", "fix")
	rec.Attr("name", "default")
	rec.RawAttr("role_arn", "aws_iam_role.config.arn")
	rg := rec.SubBlock("recording_group")
	rg.Attr("all_supported", true)
	rg.Attr("include_global_resource_types", true)

	delivery := render.NewHCLBlock("resource", "aws_config_delivery_channel", "fix")
	delivery.Attr("name", "default")
	delivery.RawAttr("s3_bucket_name", "aws_s3_bucket.config_logs.id")
	delivery.RawAttr("depends_on", "[aws_config_configuration_recorder.fix]")

	combined := rec.String() + "\n" + delivery.String()
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    combined,
		VerifyCmd:  "aws configservice describe-configuration-recorder-status",
		Notes:      "Requires an IAM role (aws_iam_role.config) with the AWS-managed AWSConfigRole policy and an S3 bucket (aws_s3_bucket.config_logs) with the AWS Config bucket policy. Both findings (recorder-on + delivery-channel) resolved by this pair.",
		Refs: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/gs-cli.html",
		},
	}, nil
}
