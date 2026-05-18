package runbook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func fixedTime() time.Time {
	return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
}

func sampleSnippets() []remediate.Snippet {
	return []remediate.Snippet{
		{
			CheckID:    "aws-s3-public-access-block",
			Format:     remediate.FormatTerraform,
			Resource:   compliancekit.ResourceRef{ID: "aws.s3.bucket.prod-data", Name: "prod-data"},
			Risk:       remediate.RiskSafe,
			Idempotent: true,
			Content:    "resource \"aws_s3_bucket_public_access_block\" \"prod_data\" {\n  bucket = \"prod-data\"\n}\n",
			VerifyCmd:  "aws s3api get-public-access-block --bucket prod-data",
			Notes:      "Blocks new public ACLs.",
		},
		{
			CheckID:  "aws-s3-public-access-block",
			Format:   remediate.FormatAWSCLI,
			Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.prod-data", Name: "prod-data"},
			Risk:     remediate.RiskSafe,
			Content:  "aws s3api put-public-access-block --bucket prod-data --public-access-block-configuration ...",
		},
		{
			CheckID:  "aws-iam-root-mfa",
			Format:   remediate.FormatTerraform,
			Resource: compliancekit.ResourceRef{ID: "aws.account.123", Name: "123"},
			Risk:     remediate.RiskManual,
			Content:  "# manual sentinel\n",
			Notes:    "Manual via console.",
		},
		{
			CheckID:  "linux-sshd-no-root-login",
			Format:   remediate.FormatBash,
			Resource: compliancekit.ResourceRef{ID: "linux.host.web-01"},
			Risk:     remediate.RiskReview,
			Content:  "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
		},
	}
}

func TestWriteProducesAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	res, err := Write(dir, sampleSnippets(), nil, Options{GeneratedAt: fixedTime(), Project: "acme"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	mustExist(t, res.RunbookPath)
	mustExist(t, res.BulkScriptPath)
	if len(res.FormatDirs) == 0 {
		t.Errorf("no per-format directories created")
	}
	for f, d := range res.FormatDirs {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("format dir for %s missing: %v", f, err)
		}
	}

	// Check that snippet files landed in per-format dirs.
	tfFiles, _ := os.ReadDir(res.FormatDirs[remediate.FormatTerraform])
	if len(tfFiles) == 0 {
		t.Errorf("no Terraform snippets in tf format dir")
	}
}

func TestRunbookMarkdownContent(t *testing.T) {
	md := renderMarkdown(sampleSnippets(), nil,
		[]remediate.Format{remediate.FormatTerraform, remediate.FormatAWSCLI, remediate.FormatBash},
		Options{GeneratedAt: fixedTime(), Project: "acme"})

	for _, want := range []string{
		"# acme — Remediation runbook",
		"## Risk classes",
		"## Table of contents",
		"## Safe (auto-apply candidates)",
		"## Review (read before applying)",
		"## Manual (POA&M-tracked)",
		"`aws-s3-public-access-block` on `prod-data`",
		"#### terraform",
		"#### aws-cli",
		"**Verify:** `aws s3api get-public-access-block",
		"```hcl",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("runbook missing %q", want)
		}
	}
}

func TestBulkScriptOnlyIncludesRiskSafe(t *testing.T) {
	res, _ := Write(t.TempDir(), sampleSnippets(), nil, Options{GeneratedAt: fixedTime()})
	body, err := os.ReadFile(res.BulkScriptPath)
	if err != nil {
		t.Fatalf("read bulk script: %v", err)
	}
	bs := string(body)
	mustContain(t, bs, "#!/usr/bin/env bash")
	mustContain(t, bs, "set -euo pipefail")
	mustContain(t, bs, "aws s3api put-public-access-block") // RiskSafe + aws-cli
	if strings.Contains(bs, "PermitRootLogin no") {
		t.Errorf("bulk script must NOT include RiskReview content")
	}
	if strings.Contains(bs, "manual sentinel") {
		t.Errorf("bulk script must NOT include RiskManual content")
	}
}

func TestUnmatchedSectionRendered(t *testing.T) {
	dir := t.TempDir()
	unmatched := []compliancekit.Finding{
		{
			CheckID:  "weird-rule",
			Resource: compliancekit.ResourceRef{ID: "weird-resource"},
			Message:  "no strategy for this rule",
		},
	}
	res, _ := Write(dir, sampleSnippets(), unmatched, Options{GeneratedAt: fixedTime()})
	body, _ := os.ReadFile(res.RunbookPath)
	if !strings.Contains(string(body), "## Unmatched — POA&M-only") {
		t.Errorf("unmatched section missing")
	}
	if !strings.Contains(string(body), "`weird-rule`") {
		t.Errorf("unmatched finding not listed")
	}
}

func TestPerFormatFilenamesAreSlugged(t *testing.T) {
	sn := remediate.Snippet{
		CheckID:  "k8s-pod-run-as-non-root",
		Format:   remediate.FormatKubectl,
		Resource: compliancekit.ResourceRef{ID: "k8s.deployment.prod.default.checkout/api:v1", Name: "checkout"},
		Risk:     remediate.RiskReview,
		Content:  "spec: ...",
	}
	got := snippetFilename(sn)
	// slashes and colons must be replaced.
	if strings.ContainsAny(got, "/: ") {
		t.Errorf("filename %q still contains unsafe chars", got)
	}
	if !strings.HasSuffix(got, ".yaml") {
		t.Errorf("expected .yaml ext, got %s", got)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s to exist: %v", filepath.Base(path), err)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("missing %q in:\n%s", needle, haystack)
	}
}
