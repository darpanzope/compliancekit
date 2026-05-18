package hcloud

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestRegistryCoverage(t *testing.T) {
	cases := []string{
		"hetzner-firewall-allow-any-source",
		"hetzner-firewall-allow-all-ports",
		"hetzner-server-no-backups",
		"hetzner-server-public-only",
	}
	for _, id := range cases {
		ss := remediate.Default.StrategiesFor(id)
		found := false
		for _, s := range ss {
			for _, f := range s.Formats() {
				if f == remediate.FormatHcloud {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CheckID %q has no hcloud strategy", id)
		}
	}
}

func TestRenderServerBackups(t *testing.T) {
	f := compliancekit.Finding{
		CheckID:  "hetzner-server-no-backups",
		Resource: compliancekit.ResourceRef{Name: "12345"},
	}
	s, err := remediate.Default.Render(f, remediate.FormatHcloud)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(s.Content, "hcloud server enable-backup 12345") {
		t.Errorf("missing enable-backup: %s", s.Content)
	}
	if s.RollbackCmd == "" {
		t.Errorf("rollback should be populated")
	}
}
