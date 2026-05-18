package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 2 — bash strategies for the 10 Spaces-depth checks.
// Spaces operations go through `aws s3api` with the Spaces endpoint
// (doctl has no spaces subcommand).

func init() {
	register("bash-do-spaces-lifecycle-no-expiration",
		[]string{"do-spaces-bucket-lifecycle-no-expiration"}, renderBashSpacesLifecycleExp)
	register("bash-do-spaces-lifecycle-no-mpu-cleanup",
		[]string{"do-spaces-bucket-lifecycle-no-mpu-cleanup"}, renderBashSpacesLifecycleMPU)
	register("bash-do-spaces-logging-self-target",
		[]string{"do-spaces-bucket-logging-self-target"}, renderBashSpacesLoggingTarget)
	register("bash-do-spaces-policy-required",
		[]string{"do-spaces-bucket-policy-required"}, renderBashSpacesPolicy)
	register("bash-do-spaces-versioning-requires-lifecycle",
		[]string{"do-spaces-bucket-versioning-requires-lifecycle"}, renderBashSpacesVersionLifecycle)
	register("bash-do-spaces-audit-pairing",
		[]string{"do-spaces-bucket-audit-pairing"}, renderBashSpacesAuditPairing)
	register("bash-do-spaces-object-lock-app-layer",
		[]string{"do-spaces-bucket-object-lock-via-app-layer"}, renderBashSpacesObjectLock)
	register("bash-do-spaces-replication-external-sync",
		[]string{"do-spaces-bucket-replication-via-external-sync"}, renderBashSpacesReplication)
	register("bash-do-spaces-mfa-delete-team-iam",
		[]string{"do-spaces-bucket-mfa-delete-via-team-iam"}, renderBashSpacesMFADelete)
	register("bash-do-spaces-encryption-key-rotation",
		[]string{"do-spaces-bucket-encryption-key-rotation-documented"}, renderBashSpacesKeyRotation)
}

const bashSpacesDefaultRegion = "nyc3"

func bashSpacesNameRegion(f compliancekit.Finding) (name, region string) {
	name = f.Resource.Name
	if name == "" {
		name = "BUCKET_NAME"
	}
	region = f.Resource.Region
	if region == "" {
		region = bashSpacesDefaultRegion
	}
	return name, region
}

func bashSpacesEndpoint(region string) string {
	return fmt.Sprintf("https://%s.digitaloceanspaces.com", region)
}

func renderBashSpacesLifecycleExp(f compliancekit.Finding) (remediate.Snippet, error) {
	name, region := bashSpacesNameRegion(f)
	body := fmt.Sprintf(`# Add (or replace) a lifecycle rule with a 365-day expiration + MPU abort.
endpoint=%q
bucket=%q
tmp="$(mktemp)"
cat > "$tmp" <<'JSON'
{"Rules":[{"ID":"expire-365d","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":365},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}}]}
JSON
aws s3api put-bucket-lifecycle-configuration --bucket "$bucket" --lifecycle-configuration "file://$tmp" --endpoint-url "$endpoint"
rm -f "$tmp"`, bashSpacesEndpoint(region), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url %s`, name, bashSpacesEndpoint(region)),
	}, nil
}

func renderBashSpacesLifecycleMPU(f compliancekit.Finding) (remediate.Snippet, error) {
	// Same shape; the rule covers both expiration + MPU.
	return renderBashSpacesLifecycleExp(f)
}

func renderBashSpacesLoggingTarget(f compliancekit.Finding) (remediate.Snippet, error) {
	name, region := bashSpacesNameRegion(f)
	body := fmt.Sprintf(`# Re-target server-access logs at a sibling bucket.
endpoint=%q
bucket=%q
target="${bucket}-access-logs"

# Create the sibling if missing.
aws s3api head-bucket --bucket "$target" --endpoint-url "$endpoint" 2>/dev/null \
  || aws s3api create-bucket --bucket "$target" --endpoint-url "$endpoint"

aws s3api put-bucket-logging --bucket "$bucket" \
  --bucket-logging-status "{\"LoggingEnabled\":{\"TargetBucket\":\"$target\",\"TargetPrefix\":\"$bucket/\"}}" \
  --endpoint-url "$endpoint"`, bashSpacesEndpoint(region), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-logging --bucket %s --endpoint-url %s`, name, bashSpacesEndpoint(region)),
		Notes:     "Idempotent — head-bucket on the sibling skips creation if already present.",
	}, nil
}

func renderBashSpacesPolicy(f compliancekit.Finding) (remediate.Snippet, error) {
	name, region := bashSpacesNameRegion(f)
	body := fmt.Sprintf(`endpoint=%q
bucket=%q
tmp="$(mktemp)"
cat > "$tmp" <<JSON
{"Version":"2012-10-17","Statement":[{"Sid":"DenyPublicReads","Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*","Condition":{"StringNotLike":{"aws:PrincipalAccount":["YOUR_DO_ACCOUNT_ID"]}}}]}
JSON
aws s3api put-bucket-policy --bucket "$bucket" --policy "file://$tmp" --endpoint-url "$endpoint"
rm -f "$tmp"`, bashSpacesEndpoint(region), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-policy --bucket %s --endpoint-url %s | jq -r .Policy`, name, bashSpacesEndpoint(region)),
		Notes:     "Replace YOUR_DO_ACCOUNT_ID in the policy before applying.",
	}, nil
}

func renderBashSpacesVersionLifecycle(f compliancekit.Finding) (remediate.Snippet, error) {
	name, region := bashSpacesNameRegion(f)
	body := fmt.Sprintf(`endpoint=%q
bucket=%q
tmp="$(mktemp)"
cat > "$tmp" <<'JSON'
{"Rules":[{"ID":"expire-noncurrent-90d","Status":"Enabled","Filter":{"Prefix":""},"NoncurrentVersionExpiration":{"NoncurrentDays":90},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}}]}
JSON
aws s3api put-bucket-lifecycle-configuration --bucket "$bucket" --lifecycle-configuration "file://$tmp" --endpoint-url "$endpoint"
rm -f "$tmp"`, bashSpacesEndpoint(region), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url %s`, name, bashSpacesEndpoint(region)),
	}, nil
}

func renderBashSpacesAuditPairing(f compliancekit.Finding) (remediate.Snippet, error) {
	name, region := bashSpacesNameRegion(f)
	body := fmt.Sprintf(`endpoint=%q
bucket=%q
target="${bucket}-access-logs"

aws s3api put-bucket-encryption --bucket "$bucket" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --endpoint-url "$endpoint"

aws s3api head-bucket --bucket "$target" --endpoint-url "$endpoint" 2>/dev/null \
  || aws s3api create-bucket --bucket "$target" --endpoint-url "$endpoint"

aws s3api put-bucket-logging --bucket "$bucket" \
  --bucket-logging-status "{\"LoggingEnabled\":{\"TargetBucket\":\"$target\",\"TargetPrefix\":\"$bucket/\"}}" \
  --endpoint-url "$endpoint"`, bashSpacesEndpoint(region), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-encryption --bucket %s --endpoint-url %s && aws s3api get-bucket-logging --bucket %s --endpoint-url %s`, name, bashSpacesEndpoint(region), name, bashSpacesEndpoint(region)),
	}, nil
}

func renderBashSpacesObjectLock(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"S3 Object Lock — DO Spaces does not implement",
		"https://www.digitalocean.com/trust",
		"Replicate audit-relevant writes to an Object-Lock-capable target (AWS S3 + Object Lock, B2, MinIO WORM)")
}

func renderBashSpacesReplication(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"S3 Cross-Region Replication — DO Spaces does not implement",
		"https://docs.digitalocean.com/products/spaces/",
		"Schedule rclone sync between source and target regions; capture last-success in the runbook")
}

func renderBashSpacesMFADelete(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"S3 MFA-Delete — DO Spaces does not implement",
		"https://cloud.digitalocean.com/account/security",
		"Enforce team 2FA + segregate delete-capable Spaces keys per bucket")
}

func renderBashSpacesKeyRotation(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"Spaces encryption key rotation",
		"https://www.digitalocean.com/trust",
		"Cite DO SOC 2 Type 2 (CC6.7) — encryption keys are platform-managed")
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage Spaces checks.
var legacySpacesBashEntries = map[string]legacyBashEntry{
	"do-spaces-bucket-cors-wildcard": {risk: remediate.RiskReview, body: "aws s3api put-bucket-cors --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --cors-configuration file://cors.json"},
	"do-spaces-bucket-no-encryption": {risk: remediate.RiskSafe, body: "aws s3api put-bucket-encryption --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"},
	"do-spaces-bucket-no-lifecycle":  {risk: remediate.RiskReview, body: "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --lifecycle-configuration file://lifecycle.json"},
	"do-spaces-bucket-no-logging":    {risk: remediate.RiskReview, body: "aws s3api put-bucket-logging --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"BUCKET-access-logs\",\"TargetPrefix\":\"BUCKET/\"}}'"},
	"do-spaces-bucket-no-versioning": {risk: remediate.RiskSafe, body: "aws s3api put-bucket-versioning --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --versioning-configuration Status=Enabled"},
	"do-spaces-bucket-public-acl":    {risk: remediate.RiskReview, body: "aws s3api put-bucket-acl --bucket BUCKET --endpoint-url https://nyc3.digitaloceanspaces.com --acl private"},
	"do-spaces-key-fullaccess":       {risk: remediate.RiskReview, body: "doctl spaces-key create scoped --grant bucket=BUCKET,permission=read\ndoctl spaces-key delete FULL_ACCESS_KEY_ID --force"},
	"do-spaces-key-too-old":          {risk: remediate.RiskReview, body: "doctl spaces-key create rotated --grant bucket=BUCKET,permission=readwrite\ndoctl spaces-key delete OLD_KEY_ID --force"},
}

func init() { registerLegacyBash(legacySpacesBashEntries) }
