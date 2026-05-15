package awscli

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

func init() {
	// S3
	register("aws-cli-s3-public-access-block",
		[]string{"aws-s3-public-access-block"}, renderS3PublicAccessBlock)
	register("aws-cli-s3-default-encryption",
		[]string{"aws-s3-default-encryption"}, renderS3Encryption)
	register("aws-cli-s3-versioning",
		[]string{"aws-s3-versioning"}, renderS3Versioning)
	register("aws-cli-s3-no-public-acls",
		[]string{"aws-s3-no-public-acls"}, renderS3PrivateACL)

	// IAM
	register("aws-cli-iam-password-policy",
		[]string{"aws-iam-password-policy"}, renderIAMPasswordPolicy)
	register("aws-cli-iam-root-manual",
		[]string{"aws-iam-root-mfa", "aws-iam-root-access-key"}, renderIAMRootManual)
	register("aws-cli-iam-unused-users",
		[]string{"aws-iam-unused-users"}, renderIAMUnusedUserManual)
	register("aws-cli-iam-access-key-age",
		[]string{"aws-iam-access-key-age"}, renderIAMAccessKeyAge)

	// CloudTrail
	register("aws-cli-cloudtrail-update",
		[]string{
			"aws-cloudtrail-enabled",
			"aws-cloudtrail-multi-region",
			"aws-cloudtrail-log-file-validation",
		},
		renderCloudTrailUpdate)

	// EC2
	register("aws-cli-ec2-ebs-encryption-default",
		[]string{"aws-ec2-ebs-encrypted"}, renderEBSEncryptionDefault)
	register("aws-cli-ec2-imdsv2",
		[]string{"aws-ec2-imdsv2-required"}, renderIMDSv2)
	register("aws-cli-ec2-sg-revoke-any",
		[]string{"aws-ec2-sg-no-ingress-from-any"}, renderSGRevokeOpenIngress)

	// RDS
	register("aws-cli-rds-deletion-protection",
		[]string{"aws-rds-deletion-protection"}, renderRDSDeletionProtection)
	register("aws-cli-rds-backup-retention",
		[]string{"aws-rds-backup-retention"}, renderRDSBackupRetention)
	register("aws-cli-rds-not-publicly-accessible",
		[]string{"aws-rds-not-publicly-accessible"}, renderRDSNotPublic)
	register("aws-cli-rds-encrypted-manual",
		[]string{"aws-rds-encrypted"}, renderRDSEncryptedManual)

	// KMS
	register("aws-cli-kms-rotation",
		[]string{"aws-kms-cmk-rotation"}, renderKMSRotation)

	// GuardDuty + Config
	register("aws-cli-guardduty-enabled",
		[]string{"aws-guardduty-enabled"}, renderGuardDuty)
	register("aws-cli-config-recorder",
		[]string{"aws-config-recorder-on", "aws-config-delivery-channel"}, renderConfigRecorderManual)
}

// --- S3 ----------------------------------------------------------------

func renderS3PublicAccessBlock(f core.Finding) (remediate.Snippet, error) {
	bucket := bucketName(f)
	cmd := fmt.Sprintf(
		`aws s3api put-public-access-block --bucket %s \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
		render.ShellQuote(bucket))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("aws s3api get-public-access-block --bucket %s", render.ShellQuote(bucket)),
		RollbackCmd: fmt.Sprintf("aws s3api delete-public-access-block --bucket %s", render.ShellQuote(bucket)),
		Notes:       "Has no effect on already-private buckets and does not block legitimate signed-URL access.",
		Refs:        []string{"https://docs.aws.amazon.com/cli/latest/reference/s3api/put-public-access-block.html"},
	}, nil
}

func renderS3Encryption(f core.Finding) (remediate.Snippet, error) {
	bucket := bucketName(f)
	cmd := fmt.Sprintf(
		`aws s3api put-bucket-encryption --bucket %s \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`,
		render.ShellQuote(bucket))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws s3api get-bucket-encryption --bucket %s", render.ShellQuote(bucket)),
		Notes:     "AES-256 SSE-S3 default. For KMS-CMK encryption substitute SSEAlgorithm=aws:kms + KMSMasterKeyID.",
	}, nil
}

func renderS3Versioning(f core.Finding) (remediate.Snippet, error) {
	bucket := bucketName(f)
	cmd := fmt.Sprintf(
		"aws s3api put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled",
		render.ShellQuote(bucket))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws s3api get-bucket-versioning --bucket %s", render.ShellQuote(bucket)),
		Notes:     "Pair with a lifecycle policy expiring noncurrent versions or storage costs grow unbounded.",
	}, nil
}

func renderS3PrivateACL(f core.Finding) (remediate.Snippet, error) {
	bucket := bucketName(f)
	cmd := fmt.Sprintf("aws s3api put-bucket-acl --bucket %s --acl private", render.ShellQuote(bucket))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("aws s3api get-bucket-acl --bucket %s", render.ShellQuote(bucket)),
		RollbackCmd: fmt.Sprintf("aws s3api put-bucket-acl --bucket %s --acl public-read", render.ShellQuote(bucket)),
		Notes:       "Breaks legitimate public-read consumers if any exist. Prefer bucket policy with explicit principals over ACLs.",
	}, nil
}

// --- IAM ---------------------------------------------------------------

func renderIAMPasswordPolicy(_ core.Finding) (remediate.Snippet, error) {
	cmd := `aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: "aws iam get-account-password-policy",
		Notes:     "Existing users with non-compliant passwords are forced to change on next sign-in. Aligned with CIS AWS Foundations 1.8-1.14.",
	}, nil
}

func renderIAMRootManual(f core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: "# Manual remediation required — root credentials are managed through the AWS console, not the CLI.\n",
		Notes: fmt.Sprintf(
			"Finding %q affects the AWS root user. There is no aws-cli command to enable root MFA or delete root access keys. Steps: 1) sign in at https://signin.aws.amazon.com/ as root; 2) open IAM → My Security Credentials; 3) enable hardware MFA and delete any active root access keys. Track via POA&M.",
			f.CheckID),
	}, nil
}

func renderIAMUnusedUserManual(f core.Finding) (remediate.Snippet, error) {
	user := f.Resource.Name
	if user == "" {
		user = "REPLACE_WITH_USERNAME"
	}
	cmd := fmt.Sprintf(
		"aws iam list-access-keys --user-name %s   # then delete each AccessKeyId you intend to revoke:\n"+
			"# aws iam delete-access-key --user-name %s --access-key-id AKIAEXAMPLE\n"+
			"# aws iam delete-login-profile --user-name %s    # remove console password\n"+
			"# aws iam delete-user --user-name %s             # final removal",
		render.ShellQuote(user), render.ShellQuote(user), render.ShellQuote(user), render.ShellQuote(user))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws iam list-access-keys --user-name %s", render.ShellQuote(user)),
		Notes:     "User deletion is destructive — review the audit trail before deleting. Prefer disabling access (delete keys + login profile) over deletion for staff who may return.",
	}, nil
}

func renderIAMAccessKeyAge(f core.Finding) (remediate.Snippet, error) {
	user := f.Resource.Name
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf("# Rotate %s's access key.\naws iam create-access-key --user-name %s\n"+
			"# distribute the new key, update applications, then:\n"+
			"# aws iam update-access-key --user-name %s --access-key-id OLD_KEY --status Inactive\n"+
			"# wait 24h to confirm nothing broke, then:\n"+
			"# aws iam delete-access-key --user-name %s --access-key-id OLD_KEY",
			user, render.ShellQuote(user), render.ShellQuote(user), render.ShellQuote(user)),
		Notes: "Key rotation is a multi-step coordinated workflow because the old key must stay valid until every consumer has the new one.",
	}, nil
}

// --- CloudTrail --------------------------------------------------------

func renderCloudTrailUpdate(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "audit"
	}
	cmd := fmt.Sprintf(
		`aws cloudtrail update-trail --name %s --is-multi-region-trail --enable-log-file-validation --include-global-service-events
aws cloudtrail start-logging --name %s`,
		render.ShellQuote(name), render.ShellQuote(name))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws cloudtrail describe-trails --trail-name-list %s", render.ShellQuote(name)),
		Notes:     "Fixes all three CloudTrail findings in two commands. Assumes the trail already exists with an S3 destination; use `aws cloudtrail create-trail` if not.",
	}, nil
}

// --- EC2 ---------------------------------------------------------------

func renderEBSEncryptionDefault(f core.Finding) (remediate.Snippet, error) {
	region := regionOf(f)
	cmd := fmt.Sprintf("aws ec2 enable-ebs-encryption-by-default --region %s", render.ShellQuote(region))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("aws ec2 get-ebs-encryption-by-default --region %s", render.ShellQuote(region)),
		RollbackCmd: fmt.Sprintf("aws ec2 disable-ebs-encryption-by-default --region %s", render.ShellQuote(region)),
		Notes:       "Account-level setting per region. New volumes are encrypted; existing volumes unchanged.",
	}, nil
}

func renderIMDSv2(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "i-EXAMPLE"
	}
	cmd := fmt.Sprintf(
		"aws ec2 modify-instance-metadata-options --instance-id %s --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1",
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws ec2 describe-instances --instance-ids %s --query 'Reservations[].Instances[].MetadataOptions'", render.ShellQuote(id)),
		Notes:     "Apps using IMDSv1 break — verify SDK versions before applying. Hop limit 1 stops container-escape via IMDS proxying.",
	}, nil
}

func renderSGRevokeOpenIngress(f core.Finding) (remediate.Snippet, error) {
	sgID := f.Resource.Name
	if sgID == "" {
		sgID = "sg-EXAMPLE"
	}
	cmd := fmt.Sprintf(
		`# Inspect first — multiple 0.0.0.0/0 rules may exist:
aws ec2 describe-security-groups --group-ids %s --query 'SecurityGroups[].IpPermissions'

# Then revoke each open rule (replace PROTO and PORT):
# aws ec2 revoke-security-group-ingress --group-id %s --protocol PROTO --port PORT --cidr 0.0.0.0/0`,
		render.ShellQuote(sgID), render.ShellQuote(sgID))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws ec2 describe-security-groups --group-ids %s", render.ShellQuote(sgID)),
		Notes:     "Cannot blindly revoke — port 80/443 on a public ELB-front SG may be legitimate. Inspect, decide, revoke. Public ingress should typically come from an ELB SG referenced by ID, not a 0.0.0.0/0 rule.",
	}, nil
}

// --- RDS ---------------------------------------------------------------

func renderRDSDeletionProtection(f core.Finding) (remediate.Snippet, error) {
	id := dbIdentifier(f)
	cmd := fmt.Sprintf(
		"aws rds modify-db-instance --db-instance-identifier %s --deletion-protection --apply-immediately",
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].DeletionProtection'", render.ShellQuote(id)),
		RollbackCmd: fmt.Sprintf(
			"aws rds modify-db-instance --db-instance-identifier %s --no-deletion-protection --apply-immediately",
			render.ShellQuote(id)),
		Notes: "Prevents accidental delete-db-instance. No effect on read replicas or snapshots.",
	}, nil
}

func renderRDSBackupRetention(f core.Finding) (remediate.Snippet, error) {
	id := dbIdentifier(f)
	cmd := fmt.Sprintf(
		"aws rds modify-db-instance --db-instance-identifier %s --backup-retention-period 7 --preferred-backup-window 03:00-04:00 --apply-immediately",
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].BackupRetentionPeriod'", render.ShellQuote(id)),
		Notes:     "7-day retention is the CIS minimum. Bumping retention triggers an immediate snapshot.",
	}, nil
}

func renderRDSNotPublic(f core.Finding) (remediate.Snippet, error) {
	id := dbIdentifier(f)
	cmd := fmt.Sprintf(
		"aws rds modify-db-instance --db-instance-identifier %s --no-publicly-accessible --apply-immediately",
		render.ShellQuote(id))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws rds describe-db-instances --db-instance-identifier %s --query 'DBInstances[0].PubliclyAccessible'", render.ShellQuote(id)),
		Notes:     "External consumers will lose DNS resolution to the DB endpoint. Move them into the VPC or use VPC peering / VPN before applying.",
	}, nil
}

func renderRDSEncryptedManual(f core.Finding) (remediate.Snippet, error) {
	id := dbIdentifier(f)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf(`# Manual remediation — RDS storage encryption requires snapshot + restore (no in-place flip).
aws rds create-db-snapshot --db-snapshot-identifier %[1]s-pre-encryption --db-instance-identifier %[1]s
aws rds copy-db-snapshot --source-db-snapshot-identifier %[1]s-pre-encryption \
  --target-db-snapshot-identifier %[1]s-encrypted --kms-key-id alias/aws/rds
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier %[1]s-new --db-snapshot-identifier %[1]s-encrypted
# Then: cut traffic over, validate, drop the original instance.
`, id),
		Notes: "Cannot enable storage encryption on an existing RDS instance. Snapshot-copy-restore is the canonical path. Plan a maintenance window.",
	}, nil
}

// --- KMS ---------------------------------------------------------------

func renderKMSRotation(f core.Finding) (remediate.Snippet, error) {
	keyID := f.Resource.Name
	if keyID == "" {
		keyID = "alias/REPLACE_WITH_KEY"
	}
	cmd := fmt.Sprintf("aws kms enable-key-rotation --key-id %s", render.ShellQuote(keyID))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("aws kms get-key-rotation-status --key-id %s", render.ShellQuote(keyID)),
		RollbackCmd: fmt.Sprintf("aws kms disable-key-rotation --key-id %s", render.ShellQuote(keyID)),
		Notes:       "Symmetric KMS keys rotate annually. Asymmetric keys do not support rotation; this command will error for those.",
	}, nil
}

// --- GuardDuty + Config -----------------------------------------------

func renderGuardDuty(f core.Finding) (remediate.Snippet, error) {
	region := regionOf(f)
	cmd := fmt.Sprintf(
		"aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES --region %s",
		render.ShellQuote(region))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: cmd,
		VerifyCmd: fmt.Sprintf("aws guardduty list-detectors --region %s", render.ShellQuote(region)),
		Notes:     "create-detector is not idempotent — check with list-detectors first. For multi-region coverage repeat per region or use Organizations + delegated admin.",
	}, nil
}

func renderConfigRecorderManual(f core.Finding) (remediate.Snippet, error) {
	region := regionOf(f)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: fmt.Sprintf(`# Multi-step: needs an IAM role + S3 bucket first.
aws iam create-role --role-name AWSConfigRole --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name AWSConfigRole --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole
aws s3 mb s3://example-config-logs --region %[1]s   # apply the Config bucket policy from AWS docs
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=$(aws iam get-role --role-name AWSConfigRole --query Role.Arn --output text) \
  --recording-group allSupported=true,includeGlobalResourceTypes=true --region %[1]s
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=example-config-logs --region %[1]s
aws configservice start-configuration-recorder --configuration-recorder-name default --region %[1]s
`, region),
		Notes: "Three prerequisites (IAM role, S3 bucket with correct bucket policy, Config-specific permissions). See linked AWS docs.",
		Refs:  []string{"https://docs.aws.amazon.com/config/latest/developerguide/gs-cli.html"},
	}, nil
}

// --- helpers ----------------------------------------------------------

func bucketName(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return f.Resource.ID
}

func dbIdentifier(f core.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return f.Resource.ID
}
