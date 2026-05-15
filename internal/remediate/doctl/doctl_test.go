package doctl

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"do-db-firewall-includes-public",
		"do-db-no-firewall-rules",
		"do-db-no-maintenance-window",
		"do-fw-allow-any-source",
		"do-fw-allow-all-ports",
		"do-droplet-no-vpc",
		"do-certificate-near-expiry",
		"do-spaces-public-acl",
		"do-app-no-alerts",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatDoctl {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no doctl strategy", id)
		}
	}
}

func TestRenderDBMaintenance(t *testing.T) {
	f := core.Finding{
		CheckID:  "do-db-no-maintenance-window",
		Resource: core.ResourceRef{Name: "db-cluster-prod"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatDoctl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "doctl databases maintenance-window update db-cluster-prod") {
		t.Errorf("missing maintenance-window update: %s", s.Content)
	}
}

func TestRenderSpacesACLUsesRegion(t *testing.T) {
	f := core.Finding{
		CheckID:  "do-spaces-public-acl",
		Resource: core.ResourceRef{Name: "assets", Region: "sfo3"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatDoctl)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "https://sfo3.digitaloceanspaces.com") {
		t.Errorf("region not threaded: %s", s.Content)
	}
}
