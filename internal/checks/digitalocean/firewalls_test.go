package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// dropletWithIP / firewall / link mirror the collector's outputs so
// the check sees the same graph shape it will see in production.

func dropletWithIP(id, name, publicIP string, firewallIDs ...string) compliancekit.Resource {
	r := compliancekit.Resource{
		ID:       "digitalocean.droplet." + id,
		Type:     docol.DropletType,
		Name:     name,
		Provider: "digitalocean",
		Attributes: map[string]any{
			"public_ipv4": publicIP,
		},
	}
	if len(firewallIDs) > 0 {
		r.Relations = map[string][]string{
			docol.EdgeFirewall: firewallIDs,
		}
	}
	return r
}

func firewall(id string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "digitalocean.firewall." + id,
		Type:     docol.FirewallType,
		Name:     id,
		Provider: "digitalocean",
	}
}

func TestNoFirewall_FailsForPublicDropletWithoutFirewall(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(dropletWithIP("1", "exposed", "203.0.113.10"))

	findings, err := NoFirewall(context.Background(), g)
	if err != nil {
		t.Fatalf("NoFirewall: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].Status; got != compliancekit.StatusFail {
		t.Errorf("status = %s, want fail", got)
	}
	if got := findings[0].Severity; got != compliancekit.SeverityHigh {
		t.Errorf("severity = %s, want high", got)
	}
}

func TestNoFirewall_PassesForPublicDropletWithFirewall(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(dropletWithIP("1", "protected", "203.0.113.10", "digitalocean.firewall.fw1"))
	g.Add(firewall("fw1"))

	findings, err := NoFirewall(context.Background(), g)
	if err != nil {
		t.Fatalf("NoFirewall: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].Status; got != compliancekit.StatusPass {
		t.Errorf("status = %s, want pass", got)
	}
}

func TestNoFirewall_SkipsPrivateOnlyDroplet(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(dropletWithIP("1", "internal-only", "")) // no public_ipv4

	findings, err := NoFirewall(context.Background(), g)
	if err != nil {
		t.Fatalf("NoFirewall: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].Status; got != compliancekit.StatusSkip {
		t.Errorf("status = %s, want skip", got)
	}
}

func TestNoFirewall_RegistersIntoDefaultRegistry(t *testing.T) {
	if _, ok := compliancekit.Lookup(CheckNoFirewall.ID); !ok {
		t.Errorf("check %q not registered", CheckNoFirewall.ID)
	}
}
