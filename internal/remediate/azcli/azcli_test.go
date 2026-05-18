package azcli

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"ingest.defender-for-cloud.STORAGE_ACCOUNT_PUBLIC_ACCESS",
		"ingest.defender-for-cloud.STORAGE_ENCRYPTION_AT_REST",
		"ingest.defender-for-cloud.SQL_TDE_ENABLED",
		"ingest.defender-for-cloud.SQL_AUDITING_ENABLED",
		"ingest.defender-for-cloud.SQL_FIREWALL_ALLOW_ALL",
		"ingest.defender-for-cloud.RBAC_BUILT_IN_OWNER",
	}
	for _, id := range cases {
		if got := remediate.Default.StrategiesFor(id); len(got) == 0 {
			t.Errorf("CheckID %q has no Azure-CLI strategy", id)
		}
	}
}

func TestRenderStorageNoPublic(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "ingest.defender-for-cloud.STORAGE_ACCOUNT_PUBLIC_ACCESS",
		Resource: compliancekit.ResourceRef{Name: "prodstore01"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatAzureCLI)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "az storage account update --name prodstore01") {
		t.Errorf("missing storage account update: %s", s.Content)
	}
	if !strings.Contains(s.Content, "--allow-blob-public-access false") {
		t.Errorf("missing public-access flag")
	}
	if s.RollbackCmd == "" {
		t.Errorf("rollback should be populated")
	}
}

func TestRenderSQLFirewallTightenIsManual(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "ingest.defender-for-cloud.SQL_FIREWALL_ALLOW_ALL",
		Resource: compliancekit.ResourceRef{Name: "sql-prod-01"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatAzureCLI)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if s.Risk != remediate.RiskManual {
		t.Errorf("Risk = %v, want manual (inspect-then-replace)", s.Risk)
	}
	if !strings.Contains(s.Content, "firewall-rule list") {
		t.Errorf("should list first: %s", s.Content)
	}
}
