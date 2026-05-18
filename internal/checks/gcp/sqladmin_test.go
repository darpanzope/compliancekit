package gcp

import (
	"context"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkSQLInstance(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "gcp.sql.instance." + name,
		Type:       gcpcol.SQLInstanceType,
		Name:       name,
		Provider:   "gcp",
		Attributes: attrs,
	}
}

func TestSQLNoPublicIP(t *testing.T) {
	cases := []struct {
		name string
		ipv4 bool
		want compliancekit.Status
	}{
		{"private", false, compliancekit.StatusPass},
		{"public", true, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkSQLInstance(c.name, map[string]any{"ipv4_enabled": c.ipv4}))
			findings, _ := SQLNoPublicIP(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestSQLAutomatedBackups(t *testing.T) {
	g := newGraphWith(
		mkSQLInstance("on", map[string]any{"backups_enabled": true}),
		mkSQLInstance("off", map[string]any{"backups_enabled": false}),
	)
	findings, _ := SQLAutomatedBackups(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "off" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSQLDeletionProtection(t *testing.T) {
	g := newGraphWith(
		mkSQLInstance("on", map[string]any{"deletion_protection_enabled": true}),
		mkSQLInstance("off", map[string]any{"deletion_protection_enabled": false}),
	)
	findings, _ := SQLDeletionProtection(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "off" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
