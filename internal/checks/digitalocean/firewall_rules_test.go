package digitalocean

import (
	"context"
	"testing"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func fwWithRules(id, name string, rules []godo.InboundRule) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "digitalocean.firewall." + id,
		Type:     docol.FirewallType,
		Name:     name,
		Provider: "digitalocean",
		Attributes: map[string]any{
			"inbound_rules": rules,
		},
	}
}

func TestSSHFromAny_FailsForOpenIPv4(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(fwWithRules("1", "open", []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "22",
			Sources:   &godo.Sources{Addresses: []string{"0.0.0.0/0"}},
		},
	}))

	findings, err := SSHFromAny(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHFromAny: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].Status; got != compliancekit.StatusFail {
		t.Errorf("status = %s, want fail", got)
	}
}

func TestSSHFromAny_FailsForOpenIPv6(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(fwWithRules("1", "open6", []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "22",
			Sources:   &godo.Sources{Addresses: []string{"::/0"}},
		},
	}))

	findings, err := SSHFromAny(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHFromAny: %v", err)
	}
	if findings[0].Status != compliancekit.StatusFail {
		t.Errorf("expected fail for ::/0 source")
	}
}

func TestSSHFromAny_FailsForAllPortsFromAny(t *testing.T) {
	// A rule of "all" ports is a superset of port 22; should be flagged.
	g := compliancekit.NewResourceGraph()
	g.Add(fwWithRules("1", "all-open", []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "all",
			Sources:   &godo.Sources{Addresses: []string{"0.0.0.0/0"}},
		},
	}))

	findings, err := SSHFromAny(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHFromAny: %v", err)
	}
	if findings[0].Status != compliancekit.StatusFail {
		t.Errorf("expected fail when 'all' ports allowed from 0.0.0.0/0")
	}
}

func TestSSHFromAny_PassesForRestrictedSource(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(fwWithRules("1", "restricted", []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "22",
			Sources:   &godo.Sources{Addresses: []string{"203.0.113.5/32"}},
		},
	}))

	findings, err := SSHFromAny(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHFromAny: %v", err)
	}
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("status = %s, want pass for narrow source", findings[0].Status)
	}
}

func TestSSHFromAny_PassesForNoSSHRule(t *testing.T) {
	g := compliancekit.NewResourceGraph()
	g.Add(fwWithRules("1", "web-only", []godo.InboundRule{
		{
			Protocol:  "tcp",
			PortRange: "443",
			Sources:   &godo.Sources{Addresses: []string{"0.0.0.0/0"}},
		},
	}))

	findings, err := SSHFromAny(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHFromAny: %v", err)
	}
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("status = %s, want pass when no SSH rule is present", findings[0].Status)
	}
}

func TestSSHFromAny_RegistersIntoDefaultRegistry(t *testing.T) {
	if _, ok := compliancekit.Lookup(CheckSSHFromAny.ID); !ok {
		t.Errorf("check %q not registered", CheckSSHFromAny.ID)
	}
}
