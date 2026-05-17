package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 2 — doctl-flavored strategies for the 10 Spaces-depth
// checks. Note: doctl itself has no `spaces` subcommand; the
// strategies wrap `aws s3api` calls with the DigitalOcean Spaces
// endpoint, mirroring the existing renderSpacesACLManual pattern.

func init() {
	register("doctl-do-spaces-lifecycle-no-expiration",
		[]string{"do-spaces-bucket-lifecycle-no-expiration"}, renderDoctlSpacesLifecycleExp)
	register("doctl-do-spaces-lifecycle-no-mpu-cleanup",
		[]string{"do-spaces-bucket-lifecycle-no-mpu-cleanup"}, renderDoctlSpacesLifecycleMPU)
	register("doctl-do-spaces-logging-self-target",
		[]string{"do-spaces-bucket-logging-self-target"}, renderDoctlSpacesLoggingTarget)
	register("doctl-do-spaces-policy-required",
		[]string{"do-spaces-bucket-policy-required"}, renderDoctlSpacesPolicy)
	register("doctl-do-spaces-versioning-requires-lifecycle",
		[]string{"do-spaces-bucket-versioning-requires-lifecycle"}, renderDoctlSpacesVersionLifecycle)
	register("doctl-do-spaces-audit-pairing",
		[]string{"do-spaces-bucket-audit-pairing"}, renderDoctlSpacesAuditPairing)
	register("doctl-do-spaces-object-lock-app-layer",
		[]string{"do-spaces-bucket-object-lock-via-app-layer"}, renderDoctlSpacesObjectLock)
	register("doctl-do-spaces-replication-external-sync",
		[]string{"do-spaces-bucket-replication-via-external-sync"}, renderDoctlSpacesReplication)
	register("doctl-do-spaces-mfa-delete-team-iam",
		[]string{"do-spaces-bucket-mfa-delete-via-team-iam"}, renderDoctlSpacesMFADelete)
	register("doctl-do-spaces-encryption-key-rotation",
		[]string{"do-spaces-bucket-encryption-key-rotation-documented"}, renderDoctlSpacesKeyRotation)
}

const spacesDefaultRegion = "nyc3"

func spacesEndpoint(region string) string {
	if region == "" {
		region = spacesDefaultRegion
	}
	return fmt.Sprintf("https://%s.digitaloceanspaces.com", region)
}

func spacesNameOrFallback(f core.Finding) (name, region string) {
	name = f.Resource.Name
	if name == "" {
		name = "BUCKET_NAME"
	}
	region = f.Resource.Region
	if region == "" {
		region = spacesDefaultRegion
	}
	return name, region
}

func renderDoctlSpacesLifecycleExp(f core.Finding) (remediate.Snippet, error) {
	name, region := spacesNameOrFallback(f)
	body := fmt.Sprintf(`# doctl has no spaces subcommand; use aws s3api against the Spaces endpoint.

cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "expire-365d",
      "Status": "Enabled",
      "Filter": { "Prefix": "" },
      "Expiration": { "Days": 365 },
      "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 7 }
    }
  ]
}
JSON

aws s3api put-bucket-lifecycle-configuration \
  --bucket %s \
  --lifecycle-configuration file://lifecycle.json \
  --endpoint-url %s`, name, spacesEndpoint(region))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url %s`, name, spacesEndpoint(region)),
		Notes:     "Replace Days:365 with your retention SLA. Spaces accepts the same shape as AWS S3.",
	}, nil
}

func renderDoctlSpacesLifecycleMPU(f core.Finding) (remediate.Snippet, error) {
	// Same shape as expiration — both rules belong in one PutBucketLifecycleConfiguration call.
	return renderDoctlSpacesLifecycleExp(f)
}

func renderDoctlSpacesLoggingTarget(f core.Finding) (remediate.Snippet, error) {
	name, region := spacesNameOrFallback(f)
	body := fmt.Sprintf(`# 1. Create a dedicated access-logs bucket (skip if it already exists).
aws s3api create-bucket --bucket %s-access-logs --endpoint-url %s

# 2. Point the source bucket's logging at the new target.
cat > logging.json <<'JSON'
{
  "LoggingEnabled": {
    "TargetBucket": "%s-access-logs",
    "TargetPrefix": "%s/"
  }
}
JSON

aws s3api put-bucket-logging \
  --bucket %s \
  --bucket-logging-status file://logging.json \
  --endpoint-url %s`, name, spacesEndpoint(region), name, name, name, spacesEndpoint(region))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-logging --bucket %s --endpoint-url %s`, name, spacesEndpoint(region)),
		Notes:     "Audit-logs bucket should have its own lifecycle (90d) and a least-privilege Spaces key.",
	}, nil
}

func renderDoctlSpacesPolicy(f core.Finding) (remediate.Snippet, error) {
	name, region := spacesNameOrFallback(f)
	body := fmt.Sprintf(`cat > policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicReads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::%s/*",
      "Condition": { "StringNotLike": { "aws:PrincipalAccount": ["YOUR_DO_ACCOUNT_ID"] } }
    }
  ]
}
JSON

aws s3api put-bucket-policy \
  --bucket %s \
  --policy file://policy.json \
  --endpoint-url %s`, name, name, spacesEndpoint(region))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-policy --bucket %s --endpoint-url %s | jq -r .Policy`, name, spacesEndpoint(region)),
		Notes:     "Replace YOUR_DO_ACCOUNT_ID with your numeric account ID. Adjust the explicit-deny statements for your threat model.",
	}, nil
}

func renderDoctlSpacesVersionLifecycle(f core.Finding) (remediate.Snippet, error) {
	name, region := spacesNameOrFallback(f)
	body := fmt.Sprintf(`cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "expire-noncurrent-90d",
      "Status": "Enabled",
      "Filter": { "Prefix": "" },
      "NoncurrentVersionExpiration": { "NoncurrentDays": 90 },
      "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 7 }
    }
  ]
}
JSON

aws s3api put-bucket-lifecycle-configuration \
  --bucket %s \
  --lifecycle-configuration file://lifecycle.json \
  --endpoint-url %s`, name, spacesEndpoint(region))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url %s`, name, spacesEndpoint(region)),
		Notes:     "Pairs versioning with bounded non-current retention so storage cost stays predictable.",
	}, nil
}

func renderDoctlSpacesAuditPairing(f core.Finding) (remediate.Snippet, error) {
	name, region := spacesNameOrFallback(f)
	body := fmt.Sprintf(`# 1. Enable SSE-S3 default encryption.
aws s3api put-bucket-encryption --bucket %s \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --endpoint-url %s

# 2. Enable server-access logging (see do-spaces-bucket-logging-self-target for the dedicated-target setup).
aws s3api put-bucket-logging --bucket %s \
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"%s-access-logs","TargetPrefix":"%s/"}}' \
  --endpoint-url %s`, name, spacesEndpoint(region), name, name, name, spacesEndpoint(region))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-encryption --bucket %s --endpoint-url %s && aws s3api get-bucket-logging --bucket %s --endpoint-url %s`, name, spacesEndpoint(region), name, spacesEndpoint(region)),
		Notes:     "Pre-create %s-access-logs first if it doesn't exist.",
	}, nil
}

func renderDoctlSpacesObjectLock(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"S3 Object Lock — DO Spaces returns 501 on PutBucketObjectLockConfiguration",
		"https://www.digitalocean.com/trust",
		"Replicate audit-relevant writes off-Spaces to an Object-Lock-capable target (AWS S3 with Object Lock, Backblaze B2, MinIO WORM)")
}

func renderDoctlSpacesReplication(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"S3 Cross-Region Replication — DO Spaces does not implement",
		"https://docs.digitalocean.com/products/spaces/",
		"Run an rclone sync cron between source and target regions; record schedule + last-success in the runbook")
}

func renderDoctlSpacesMFADelete(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"S3 MFA-Delete — DO Spaces does not implement",
		"https://cloud.digitalocean.com/account/security",
		"Enforce team 2FA + issue scoped Spaces keys with delete privilege per bucket")
}

func renderDoctlSpacesKeyRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"Spaces SSE key rotation",
		"https://www.digitalocean.com/trust",
		"Cite DO's SOC 2 Type 2 report (CC6.7) — encryption keys are platform-managed")
}
