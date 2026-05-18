package awscli

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"aws-s3-public-access-block", "aws-s3-default-encryption",
		"aws-s3-versioning", "aws-s3-no-public-acls",
		"aws-iam-password-policy", "aws-iam-root-mfa", "aws-iam-root-access-key",
		"aws-iam-unused-users", "aws-iam-access-key-age",
		"aws-cloudtrail-enabled", "aws-cloudtrail-multi-region",
		"aws-cloudtrail-log-file-validation",
		"aws-ec2-ebs-encrypted", "aws-ec2-imdsv2-required",
		"aws-ec2-sg-no-ingress-from-any",
		"aws-rds-deletion-protection", "aws-rds-backup-retention",
		"aws-rds-not-publicly-accessible", "aws-rds-encrypted",
		"aws-kms-cmk-rotation", "aws-guardduty-enabled",
		"aws-config-recorder-on", "aws-config-delivery-channel",
	}
	for _, id := range cases {
		// Walk strategies for the CheckID and require at least one
		// claim FormatAWSCLI; this rules out Terraform-only matches.
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatAWSCLI {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no AWS-CLI strategy", id)
		}
	}
}

func TestRenderS3PublicAccessBlock(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "aws-s3-public-access-block",
		Resource: compliancekit.ResourceRef{Name: "prod-bucket"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatAWSCLI)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "put-public-access-block") {
		t.Errorf("Content missing put-public-access-block: %s", s.Content)
	}
	if !strings.Contains(s.Content, "prod-bucket") {
		t.Errorf("Content missing bucket name")
	}
	if s.VerifyCmd == "" || s.RollbackCmd == "" {
		t.Errorf("VerifyCmd or RollbackCmd unpopulated")
	}
}

func TestRenderEBSDefaultEncryptionUsesRegion(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "aws-ec2-ebs-encrypted",
		Resource: compliancekit.ResourceRef{Region: "eu-west-1"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatAWSCLI)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "--region eu-west-1") {
		t.Errorf("Region not threaded: %s", s.Content)
	}
}

func TestRenderManualSentinels(t *testing.T) {
	manualIDs := []string{
		"aws-iam-root-mfa",
		"aws-iam-root-access-key",
		"aws-iam-unused-users",
		"aws-iam-access-key-age",
		"aws-ec2-sg-no-ingress-from-any",
		"aws-rds-encrypted",
	}
	for _, id := range manualIDs {
		f := compliancekit.Finding{CheckID: id, Resource: compliancekit.ResourceRef{Name: "example"}}
		s, err := remediate.Default.Render(f, remediate.FormatAWSCLI)
		if err != nil {
			t.Errorf("Render(%q): %v", id, err)
			continue
		}
		if s.Risk != remediate.RiskManual {
			t.Errorf("%q Risk = %v, want manual", id, s.Risk)
		}
	}
}

func TestRenderCloudTrailGrouped(t *testing.T) {
	cases := []string{
		"aws-cloudtrail-enabled",
		"aws-cloudtrail-multi-region",
		"aws-cloudtrail-log-file-validation",
	}
	var first string
	for i, id := range cases {
		f := compliancekit.Finding{CheckID: id, Resource: compliancekit.ResourceRef{Name: "main-trail"}}
		s, err := remediate.Default.Render(f, remediate.FormatAWSCLI)
		if err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		if i == 0 {
			first = s.Content
		} else if s.Content != first {
			t.Errorf("%q content diverges from first", id)
		}
		if !strings.Contains(s.Content, "is-multi-region-trail") {
			t.Errorf("%q missing multi-region flag", id)
		}
	}
}
