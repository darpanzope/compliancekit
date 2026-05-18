package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 11 — coverage for the three real-data firewall-depth
// checks. Each builds a host Resource with the firewall attr map
// shape the linux collector emits.

func hostWithFirewall(name string, fw map[string]any, rel linuxcol.OSRelease) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable":  true,
			"firewall":   fw,
			"os_release": rel,
		},
	}
}

func TestFirewallUFWDefaultDenyOutgoing(t *testing.T) {
	cases := []struct {
		name string
		fw   map[string]any
		want compliancekit.Status
	}{
		{"ufw active + outgoing=deny → pass", map[string]any{"ufw_active": true, "ufw_default_outgoing": "deny"}, compliancekit.StatusPass},
		{"ufw active + outgoing=allow → fail", map[string]any{"ufw_active": true, "ufw_default_outgoing": "allow"}, compliancekit.StatusFail},
		{"ufw inactive → skip (other firewall)", map[string]any{"ufw_active": false}, compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, hostWithFirewall("h", c.fw, linuxcol.OSRelease{ID: "ubuntu"}))
			findings, _ := FirewallUFWDefaultDenyOutgoing(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (msg=%q)", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallUFWDefaultDenyOutgoing_ErrorOnMissingAttr(t *testing.T) {
	g := newGraph(t, compliancekit.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	})
	findings, _ := FirewallUFWDefaultDenyOutgoing(context.Background(), g)
	if findings[0].Status != compliancekit.StatusError {
		t.Errorf("status=%v want StatusError when firewall attr absent", findings[0].Status)
	}
}

func TestFirewallSomeActive(t *testing.T) {
	cases := []struct {
		name string
		fw   map[string]any
		want compliancekit.Status
	}{
		{"ufw on → pass", map[string]any{"ufw_active": true, "nftables_active": false}, compliancekit.StatusPass},
		{"nftables on → pass", map[string]any{"ufw_active": false, "nftables_active": true}, compliancekit.StatusPass},
		{"both off → fail", map[string]any{"ufw_active": false, "nftables_active": false}, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, hostWithFirewall("h", c.fw, linuxcol.OSRelease{ID: "ubuntu"}))
			findings, _ := FirewallSomeActive(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (msg=%q)", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallNFTablesOnRHEL(t *testing.T) {
	rhel := linuxcol.OSRelease{ID: "rhel", VersionID: "9"}
	ubuntu := linuxcol.OSRelease{ID: "ubuntu", VersionID: "22.04"}
	cases := []struct {
		name string
		rel  linuxcol.OSRelease
		fw   map[string]any
		want compliancekit.Status
	}{
		{"RHEL + nftables on → pass", rhel, map[string]any{"nftables_active": true}, compliancekit.StatusPass},
		{"RHEL + nftables off → fail", rhel, map[string]any{"nftables_active": false}, compliancekit.StatusFail},
		{"Ubuntu → skip (N/A)", ubuntu, map[string]any{"nftables_active": false}, compliancekit.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, hostWithFirewall("h", c.fw, c.rel))
			findings, _ := FirewallNFTablesOnRHEL(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (msg=%q)", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}
