package terraform

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// fixture is a small helper for table-driven tests below.
func fixture(checkID, resourceName string) core.Finding {
	return core.Finding{
		CheckID: checkID,
		Resource: core.ResourceRef{
			ID:   "aws.s3.bucket." + resourceName,
			Name: resourceName,
			Type: "aws.s3.bucket",
		},
	}
}

func TestRegistryCoverage(t *testing.T) {
	// Smoke test: every CheckID we claim to support resolves to a
	// strategy in the Default registry. Catches typos at unit-test
	// time rather than at user-facing rendering time.
	cases := []string{
		// AWS
		"aws-s3-public-access-block",
		"aws-s3-default-encryption",
		"aws-s3-versioning",
		"aws-s3-logging",
		"aws-s3-no-public-acls",
		"aws-iam-password-policy",
		"aws-iam-root-mfa",
		"aws-iam-root-access-key",
		"aws-cloudtrail-enabled",
		"aws-cloudtrail-multi-region",
		"aws-cloudtrail-log-file-validation",
		"aws-ec2-ebs-encrypted",
		"aws-ec2-imdsv2-required",
		"aws-rds-deletion-protection",
		"aws-rds-backup-retention",
		"aws-rds-not-publicly-accessible",
		"aws-rds-encrypted",
		"aws-kms-cmk-rotation",
		"aws-guardduty-enabled",
		"aws-config-recorder-on",
		// GCP
		"gcp-storage-public-access-prevention",
		"gcp-storage-uniform-bucket-level-access",
		"gcp-storage-versioning",
		"gcp-storage-logging",
		"gcp-sql-no-public-ip",
		"gcp-sql-deletion-protection",
		"gcp-sql-automated-backups",
		"gcp-compute-shielded-vm",
		"gcp-bigquery-default-cmek",
		"gcp-kms-key-rotation",
		"gcp-iam-no-primitive-roles",
		// DO
		"do-db-tls-disabled",
		"do-db-no-vpc",
		"do-db-no-maintenance-window",
		"do-spaces-public-acl",
		"do-droplet-no-vpc",
		"do-fw-allow-any-source",
		"do-app-no-vpc",
		"do-domain-no-caa",
		// Hetzner
		"hetzner-firewall-allow-any-source",
		"hetzner-server-public-only",
		"hetzner-server-no-backups",
	}
	for _, id := range cases {
		got := remediate.Default.StrategiesFor(id)
		if len(got) == 0 {
			t.Errorf("CheckID %q has no registered Terraform strategy", id)
		}
	}
}

func TestRenderAWSS3PublicAccessBlock(t *testing.T) {
	f := fixture("aws-s3-public-access-block", "my-prod-bucket")
	snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if snip.Risk != remediate.RiskSafe {
		t.Errorf("Risk = %v, want safe", snip.Risk)
	}
	if !snip.Idempotent {
		t.Errorf("Idempotent should be true for this fix")
	}
	mustContain(t, snip.Content, `resource "aws_s3_bucket_public_access_block"`)
	mustContain(t, snip.Content, `"my-prod-bucket"`)
	mustContain(t, snip.Content, "block_public_acls")
	mustContain(t, snip.Content, "block_public_policy")
	mustContain(t, snip.Content, "restrict_public_buckets")
	if snip.VerifyCmd == "" {
		t.Errorf("VerifyCmd should be populated")
	}
	if !strings.Contains(snip.VerifyCmd, "get-public-access-block") {
		t.Errorf("VerifyCmd content: %q", snip.VerifyCmd)
	}
}

func TestRenderManualSentinels(t *testing.T) {
	// RDS-encrypted, IAM-root, GCP-iam-primitive, DO-app-no-vpc all
	// emit RiskManual snippets — these are the integration points
	// with POA&M (Phase 9).
	manualIDs := []string{
		"aws-rds-encrypted",
		"aws-iam-root-mfa",
		"aws-iam-root-access-key",
		"gcp-iam-no-primitive-roles",
		"do-app-no-vpc",
	}
	for _, id := range manualIDs {
		f := fixture(id, "example-resource")
		snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
		if err != nil {
			t.Errorf("Render(%q): %v", id, err)
			continue
		}
		if snip.Risk != remediate.RiskManual {
			t.Errorf("%q Risk = %v, want manual", id, snip.Risk)
		}
		if snip.Notes == "" {
			t.Errorf("%q Notes should explain the manual action", id)
		}
	}
}

func TestRenderHCLDeterministic(t *testing.T) {
	// Property: rendering the same finding twice produces byte-identical
	// output. v0.15 evidence pack diffs assume this — non-determinism
	// would produce spurious "remediation changed" warnings.
	f := fixture("aws-kms-cmk-rotation", "alias/prod-cmk")
	first, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("first Render: %v", err)
	}
	second, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("second Render: %v", err)
	}
	if first.Content != second.Content {
		t.Errorf("non-deterministic render:\nfirst:\n%s\nsecond:\n%s",
			first.Content, second.Content)
	}
}

func TestRenderGCPStoragePAP(t *testing.T) {
	f := core.Finding{
		CheckID:  "gcp-storage-public-access-prevention",
		Resource: core.ResourceRef{Name: "data-lake-prod", Type: "gcp.storage.bucket"},
	}
	snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, snip.Content, `"data-lake-prod"`)
	mustContain(t, snip.Content, "public_access_prevention")
	mustContain(t, snip.Content, "enforced")
}

func TestRenderDOSpacesPrivate(t *testing.T) {
	f := core.Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: core.ResourceRef{Name: "assets-cdn", Type: "digitalocean.spaces_bucket"},
	}
	snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, snip.Content, "digitalocean_spaces_bucket")
	mustContain(t, snip.Content, `"private"`)
}

func TestRenderCloudTrailMultiCheck(t *testing.T) {
	// One strategy covers all three CloudTrail CheckIDs — verify each
	// resolves to the same Content.
	cases := []string{
		"aws-cloudtrail-enabled",
		"aws-cloudtrail-multi-region",
		"aws-cloudtrail-log-file-validation",
	}
	contents := make([]string, 0, len(cases))
	for _, id := range cases {
		f := core.Finding{
			CheckID:  id,
			Resource: core.ResourceRef{Name: "main-trail"},
		}
		snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
		if err != nil {
			t.Fatalf("%q render: %v", id, err)
		}
		mustContain(t, snip.Content, "is_multi_region_trail")
		mustContain(t, snip.Content, "enable_log_file_validation")
		contents = append(contents, snip.Content)
	}
	if contents[0] != contents[1] || contents[1] != contents[2] {
		t.Errorf("shared strategy should produce identical content for grouped CheckIDs")
	}
}

func TestRenderResourceIDFallback(t *testing.T) {
	// When Resource.Name is empty, strategies should fall back to
	// Resource.ID rather than emitting an empty bucket attribute.
	f := core.Finding{
		CheckID: "aws-s3-public-access-block",
		Resource: core.ResourceRef{
			ID: "aws.s3.bucket.orphan-no-name",
		},
	}
	snip, err := remediate.Default.Render(f, remediate.FormatTerraform)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, snip.Content, `"aws.s3.bucket.orphan-no-name"`)
}

func TestTfIdent(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "fix"},
		{"my-bucket", "my_bucket"},
		{"My.Bucket-123", "my_bucket_123"},
		{"123starts-with-digit", "_123starts_with_digit"},
		{"---", "fix"},
	}
	for _, c := range cases {
		got := tfIdent(c.in)
		if got != c.want {
			t.Errorf("tfIdent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("missing substring %q in:\n%s", needle, haystack)
	}
}
