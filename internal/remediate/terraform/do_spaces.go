package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 2 — Terraform strategies for the 10 Spaces-depth checks.
//
// Spaces buckets in TF are `digitalocean_spaces_bucket`; the provider
// surfaces lifecycle_rule / cors_rule / versioning / logging blocks
// inline. Object-Lock, CRR, MFA-Delete, transfer-acceleration are NOT
// surfaced because DO Spaces does not implement them.

func init() {
	register("tf-do-spaces-lifecycle-no-expiration",
		[]string{"do-spaces-bucket-lifecycle-no-expiration"}, renderTFSpacesLifecycleExpiration)
	register("tf-do-spaces-lifecycle-no-mpu-cleanup",
		[]string{"do-spaces-bucket-lifecycle-no-mpu-cleanup"}, renderTFSpacesLifecycleMPU)
	register("tf-do-spaces-logging-self-target",
		[]string{"do-spaces-bucket-logging-self-target"}, renderTFSpacesLoggingTarget)
	register("tf-do-spaces-policy-required",
		[]string{"do-spaces-bucket-policy-required"}, renderTFSpacesPolicy)
	register("tf-do-spaces-versioning-requires-lifecycle",
		[]string{"do-spaces-bucket-versioning-requires-lifecycle"}, renderTFSpacesVersioningLifecycle)
	register("tf-do-spaces-audit-pairing",
		[]string{"do-spaces-bucket-audit-pairing"}, renderTFSpacesAuditPairing)
	register("tf-do-spaces-object-lock-app-layer",
		[]string{"do-spaces-bucket-object-lock-via-app-layer"}, renderTFSpacesObjectLock)
	register("tf-do-spaces-replication-external-sync",
		[]string{"do-spaces-bucket-replication-via-external-sync"}, renderTFSpacesReplication)
	register("tf-do-spaces-mfa-delete-team-iam",
		[]string{"do-spaces-bucket-mfa-delete-via-team-iam"}, renderTFSpacesMFADelete)
	register("tf-do-spaces-encryption-key-rotation",
		[]string{"do-spaces-bucket-encryption-key-rotation-documented"}, renderTFSpacesKeyRotation)
}

func tfSpacesBucketLifecycleBlock(name string) string {
	return fmt.Sprintf(`resource "digitalocean_spaces_bucket" %q {
  name   = %q
  region = "nyc3"
  # NOTE: add to your existing bucket — apply via 'terraform apply' to merge.
  lifecycle_rule {
    id      = "expire-objects"
    enabled = true
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload_days = 7
  }
}
`, tfIdent(name), name)
}

func renderTFSpacesLifecycleExpiration(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content:   tfSpacesBucketLifecycleBlock(name),
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url https://nyc3.digitaloceanspaces.com`, name),
		Notes:     "Replace days=365 with your retention policy. Apply against the EXISTING bucket — TF will diff into the lifecycle attribute.",
		Refs:      []string{"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket#lifecycle_rule"},
	}, nil
}

func renderTFSpacesLifecycleMPU(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content:   tfSpacesBucketLifecycleBlock(name),
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-lifecycle-configuration --bucket %s --endpoint-url https://nyc3.digitaloceanspaces.com`, name),
		Notes:     "abort_incomplete_multipart_upload_days=7 catches orphaned multipart uploads weekly.",
	}, nil
}

func renderTFSpacesLoggingTarget(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	body := fmt.Sprintf(`resource "digitalocean_spaces_bucket" "audit_logs" {
  name   = "%s-access-logs"
  region = "nyc3"
  acl    = "private"
  lifecycle_rule {
    id      = "expire-90d"
    enabled = true
    expiration { days = 90 }
  }
}

resource "digitalocean_spaces_bucket" %q {
  name   = %q
  region = "nyc3"
  logging {
    target_bucket = digitalocean_spaces_bucket.audit_logs.name
    target_prefix = "%s/"
  }
}
`, name, tfIdent(name), name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content:   body,
		VerifyCmd: fmt.Sprintf(`aws s3api get-bucket-logging --bucket %s --endpoint-url https://nyc3.digitaloceanspaces.com`, name),
		Notes:     "Creates a dedicated <bucket>-access-logs sibling with 90d retention and points the original bucket at it.",
	}, nil
}

func renderTFSpacesPolicy(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	body := fmt.Sprintf(`# Bucket policies on Spaces are NOT natively expressed in the
# digitalocean Terraform provider. The provider supports the bucket
# resource but the policy must be applied via the aws_s3_bucket_policy
# from the AWS provider with the Spaces endpoint, or via aws s3api.
#
# Example bash apply:
#   aws s3api put-bucket-policy --bucket %s \
#     --policy file://policy.json \
#     --endpoint-url https://nyc3.digitaloceanspaces.com
#
# policy.json — explicit-deny posture:
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Sid": "DenyPublicReads",
#         "Effect": "Deny",
#         "Principal": "*",
#         "Action": "s3:GetObject",
#         "Resource": "arn:aws:s3:::%s/*",
#         "Condition": { "StringNotLike": { "aws:PrincipalAccount": ["YOUR_ACCOUNT_ID"] } }
#       }
#     ]
#   }
`, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: body,
		Notes:   "DO provider has no spaces_bucket_policy resource yet (track digitalocean/terraform-provider-digitalocean#XXX). Apply via aws CLI.",
		Refs:    []string{"https://docs.digitalocean.com/products/spaces/how-to/manage-access/"},
	}, nil
}

func renderTFSpacesVersioningLifecycle(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	body := fmt.Sprintf(`resource "digitalocean_spaces_bucket" %q {
  name   = %q
  region = "nyc3"
  versioning { enabled = true }
  lifecycle_rule {
    id      = "expire-noncurrent-versions"
    enabled = true
    noncurrent_version_expiration { days = 90 }
    abort_incomplete_multipart_upload_days = 7
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: body,
		Notes:   "Pairs versioning with a 90d non-current version expiration so storage cost stays bounded.",
		Refs:    []string{"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket"},
	}, nil
}

func renderTFSpacesAuditPairing(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "BUCKET_NAME")
	body := fmt.Sprintf(`# Enable BOTH encryption (SSE-S3 via aws s3api) AND logging.
# Terraform side:

resource "digitalocean_spaces_bucket" %q {
  name   = %q
  region = "nyc3"
  acl    = "private"
  logging {
    target_bucket = digitalocean_spaces_bucket.audit_logs.name
    target_prefix = "%s/"
  }
}

# Apply encryption side via:
#   aws s3api put-bucket-encryption --bucket %s \
#     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
#     --endpoint-url https://nyc3.digitaloceanspaces.com
`, tfIdent(name), name, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: body,
		Notes:   "DO provider supports logging inline but not server-side encryption. Apply encryption via aws s3api as shown.",
	}, nil
}

func renderTFSpacesObjectLock(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO Spaces does not implement S3 Object Lock — there is no TF resource to enable it",
		"https://www.digitalocean.com/trust",
		"replicate audit-relevant writes off-Spaces to an Object-Lock-capable target")
}

func renderTFSpacesReplication(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO Spaces does not implement S3 CRR — no TF resource exists",
		"https://docs.digitalocean.com/products/spaces/",
		"run rclone sync on a cron between source and target regions / providers")
}

func renderTFSpacesMFADelete(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"DO Spaces does not implement S3 MFA-Delete — no TF surface",
		"https://cloud.digitalocean.com/account/security",
		"enforce team 2FA + segregate delete-capable Spaces keys per bucket")
}

func renderTFSpacesKeyRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Spaces encryption keys are platform-managed; key rotation is DO's responsibility",
		"https://www.digitalocean.com/trust",
		"cite DO's current SOC 2 Type 2 report (CC6.7) in the audit narrative")
}

// tfNameOrFallback returns the resource name or the supplied
// placeholder. Shared across the Phase 2 strategies to keep render
// functions one-liners. The placeholder argument is kept (always
// "BUCKET_NAME" today) so future strategies can pass a more specific
// hint without rewriting the helper signature.
func tfNameOrFallback(f core.Finding, fallback string) string { //nolint:unparam // fallback varies in future strategies
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	if f.Resource.ID != "" {
		return f.Resource.ID
	}
	return fallback
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage Spaces checks.
var legacySpacesTFEntries = map[string]legacyTFEntry{
	"do-spaces-bucket-cors-wildcard": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_spaces_bucket\" \"app\" {\n  cors_rule {\n    allowed_methods = [\"GET\"]\n    allowed_origins = [\"https://app.example.com\"]\n    max_age_seconds = 3600\n  }\n}\n"},
	"do-spaces-bucket-no-encryption": {risk: remediate.RiskSafe,
		content: "# Spaces SSE applied via aws s3api put-bucket-encryption against the Spaces endpoint.\n# The DO TF provider does not expose it; see doctl strategy."},
	"do-spaces-bucket-no-lifecycle": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_spaces_bucket\" \"app\" {\n  lifecycle_rule {\n    id      = \"expire-365d\"\n    enabled = true\n    expiration { days = 365 }\n    abort_incomplete_multipart_upload_days = 7\n  }\n}\n"},
	"do-spaces-bucket-no-logging": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_spaces_bucket\" \"app\" {\n  logging {\n    target_bucket = digitalocean_spaces_bucket.access_logs.name\n    target_prefix = \"app/\"\n  }\n}\n"},
	"do-spaces-bucket-no-versioning": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_spaces_bucket\" \"app\" {\n  versioning { enabled = true }\n}\n"},
	"do-spaces-bucket-public-acl": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_spaces_bucket\" \"app\" {\n  acl = \"private\"\n}\n"},
	"do-spaces-key-fullaccess": {risk: remediate.RiskReview,
		content: "# Issue scoped key + delete the full-access one via doctl:\n# doctl spaces-key create scoped --grant bucket=BUCKET,permission=read\n# doctl spaces-key delete FULL_ACCESS_KEY_ID --force"},
	"do-spaces-key-too-old": {risk: remediate.RiskReview,
		content: "# Rotate via doctl; key creation is not a TF resource.\n# doctl spaces-key create rotated --grant bucket=BUCKET,permission=readwrite"},
}

func init() { registerLegacyTF(legacySpacesTFEntries) }
