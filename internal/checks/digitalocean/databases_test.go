package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkDB(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.database." + name,
		Type:       docol.DatabaseType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestDBHasFirewallRules(t *testing.T) {
	g := newAccountGraph(
		mkDB("locked", map[string]any{"firewall_rule_count": 2}),
		mkDB("open", map[string]any{"firewall_rule_count": 0}),
	)
	findings, _ := DBHasFirewallRules(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "open" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBFirewallNoPublicCIDR(t *testing.T) {
	g := newAccountGraph(
		mkDB("clean", map[string]any{"firewall_rules": []map[string]any{
			{"type": "droplet", "value": "12345"},
		}}),
		mkDB("public", map[string]any{"firewall_rules": []map[string]any{
			{"type": "ip_addr", "value": "0.0.0.0/0"},
		}}),
		mkDB("ipv6-public", map[string]any{"firewall_rules": []map[string]any{
			{"type": "ip_addr", "value": "::/0"},
		}}),
	)
	findings, _ := DBFirewallNoPublicCIDR(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "public" || f.Resource.Name == "ipv6-public" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBTLSEnabled(t *testing.T) {
	g := newAccountGraph(
		mkDB("tls", map[string]any{"public_ssl": true}),
		mkDB("no-tls", map[string]any{"public_ssl": false}),
	)
	findings, _ := DBTLSEnabled(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "no-tls" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBInVPC(t *testing.T) {
	g := newAccountGraph(
		mkDB("vpc", map[string]any{"vpc_uuid": "v-1"}),
		mkDB("legacy", map[string]any{"vpc_uuid": ""}),
	)
	findings, _ := DBInVPC(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "legacy" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBEngineNotEOL(t *testing.T) {
	cases := []struct {
		name    string
		engine  string
		version string
		want    compliancekit.Status
	}{
		{"pg-current", "pg", "16", compliancekit.StatusPass},
		{"pg-eol", "pg", "12", compliancekit.StatusFail},
		{"mysql-eol", "mysql", "5.7", compliancekit.StatusFail},
		{"mongodb-current", "mongodb", "7", compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDB(c.name, map[string]any{"engine": c.engine, "version": c.version}))
			findings, _ := DBEngineNotEOL(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestDBMaintenanceWindow(t *testing.T) {
	g := newAccountGraph(
		mkDB("scheduled", map[string]any{"maintenance_day": "sunday", "maintenance_hour": "02:00"}),
		mkDB("unset", map[string]any{"maintenance_day": "", "maintenance_hour": ""}),
	)
	findings, _ := DBMaintenanceWindow(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "unset" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBMultiNode(t *testing.T) {
	g := newAccountGraph(
		mkDB("ha", map[string]any{"num_nodes": 3}),
		mkDB("single", map[string]any{"num_nodes": 1}),
	)
	findings, _ := DBMultiNode(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "single" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDBOnlyDOTrustedSources(t *testing.T) {
	g := newAccountGraph(
		mkDB("named", map[string]any{"firewall_rules": []map[string]any{
			{"type": "droplet", "value": "1"},
		}}),
		mkDB("ip-only", map[string]any{"firewall_rules": []map[string]any{
			{"type": "ip_addr", "value": "10.0.0.0/8"},
		}}),
		mkDB("mixed", map[string]any{"firewall_rules": []map[string]any{
			{"type": "droplet", "value": "1"},
			{"type": "ip_addr", "value": "10.0.0.0/8"},
		}}),
	)
	findings, _ := DBOnlyDOTrustedSources(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "ip-only" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v: %s", f.Resource.Name, f.Status, f.Message)
		}
	}
}
