package gcloud

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"gcp-storage-public-access-prevention",
		"gcp-storage-uniform-bucket-level-access",
		"gcp-storage-versioning",
		"gcp-sql-no-public-ip",
		"gcp-sql-deletion-protection",
		"gcp-sql-automated-backups",
		"gcp-compute-shielded-vm",
		"gcp-compute-os-login-enabled",
		"gcp-compute-no-ssh-from-any",
		"gcp-kms-key-rotation",
		"gcp-iam-no-primitive-roles",
		"gcp-iam-no-broad-token-creator",
		"gcp-iam-no-user-managed-sa-keys",
		"gcp-iam-sa-key-age",
		"gcp-logging-sink-exists",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatGCloud {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no gcloud strategy", id)
		}
	}
}

func TestRenderStoragePAP(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "gcp-storage-public-access-prevention",
		Resource: compliancekit.ResourceRef{Name: "data-lake-prod"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatGCloud)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "gs://data-lake-prod") {
		t.Errorf("missing bucket URI: %s", s.Content)
	}
	if !strings.Contains(s.Content, "--public-access-prevention") {
		t.Errorf("missing PAP flag")
	}
	if s.RollbackCmd == "" {
		t.Errorf("rollback should be populated")
	}
}

func TestRenderManualSentinels(t *testing.T) {
	manualIDs := []string{
		"gcp-iam-no-primitive-roles",
		"gcp-iam-no-broad-token-creator",
		"gcp-iam-no-user-managed-sa-keys",
		"gcp-iam-sa-key-age",
	}
	for _, id := range manualIDs {
		f := compliancekit.Finding{CheckID: id, Resource: compliancekit.ResourceRef{Name: "ex"}}
		s, err := remediate.Default.Render(f, remediate.FormatGCloud)
		if err != nil {
			t.Errorf("%q: %v", id, err)
			continue
		}
		if s.Risk != remediate.RiskManual {
			t.Errorf("%q Risk = %v, want manual", id, s.Risk)
		}
	}
}

func TestRenderShieldedVMUsesZone(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "gcp-compute-shielded-vm",
		Resource: compliancekit.ResourceRef{Name: "vm-1", Region: "europe-west1-b"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatGCloud)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "--zone=europe-west1-b") {
		t.Errorf("zone not threaded: %s", s.Content)
	}
}
