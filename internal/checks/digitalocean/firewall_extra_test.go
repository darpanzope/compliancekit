package digitalocean

import (
	"context"
	"testing"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkFirewall(name string, attrs map[string]any, tags []string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.firewall." + name,
		Type:       docol.FirewallType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
		Tags:       tags,
	}
}

func inbound(protocol, ports string, sources []string) godo.InboundRule {
	return godo.InboundRule{
		Protocol:  protocol,
		PortRange: ports,
		Sources:   &godo.Sources{Addresses: sources},
	}
}

func outbound(protocol, ports string, dests []string) godo.OutboundRule {
	return godo.OutboundRule{
		Protocol:     protocol,
		PortRange:    ports,
		Destinations: &godo.Destinations{Addresses: dests},
	}
}

func TestFirewallRDPFromAny(t *testing.T) {
	cases := []struct {
		name  string
		rules []godo.InboundRule
		want  compliancekit.Status
	}{
		{"rdp-from-any", []godo.InboundRule{inbound("tcp", "3389", []string{"0.0.0.0/0"})}, compliancekit.StatusFail},
		{"rdp-from-ipv6-any", []godo.InboundRule{inbound("tcp", "3389", []string{"::/0"})}, compliancekit.StatusFail},
		{"rdp-from-bastion", []godo.InboundRule{inbound("tcp", "3389", []string{"203.0.113.0/24"})}, compliancekit.StatusPass},
		{"no-rdp", []godo.InboundRule{inbound("tcp", "22", []string{"0.0.0.0/0"})}, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFirewall(c.name, map[string]any{"inbound_rules": c.rules}, nil))
			findings, _ := FirewallRDPFromAny(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallAnyFromAny(t *testing.T) {
	cases := []struct {
		name  string
		rules []godo.InboundRule
		want  compliancekit.Status
	}{
		{"any-from-any", []godo.InboundRule{inbound("tcp", "all", []string{"0.0.0.0/0"})}, compliancekit.StatusFail},
		{"any-from-restricted", []godo.InboundRule{inbound("tcp", "all", []string{"10.0.0.0/8"})}, compliancekit.StatusPass},
		{"single-port-from-any", []godo.InboundRule{inbound("tcp", "443", []string{"0.0.0.0/0"})}, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFirewall(c.name, map[string]any{"inbound_rules": c.rules}, nil))
			findings, _ := FirewallAnyFromAny(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestPortRangeSize(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"22", 1},
		{"20-30", 11},
		{"1024-65535", 64512},
		{"all", 65536},
		{"0", 65536},
		{"junk", 0},
		{"30-20", 0}, // reversed
	}
	for _, c := range cases {
		got := portRangeSize(c.in)
		if got != c.want {
			t.Errorf("portRangeSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFirewallBroadPortRange(t *testing.T) {
	cases := []struct {
		name  string
		rules []godo.InboundRule
		want  compliancekit.Status
	}{
		{"narrow-ok", []godo.InboundRule{inbound("tcp", "20-30", []string{"0.0.0.0/0"})}, compliancekit.StatusPass},
		{"wide-from-public", []godo.InboundRule{inbound("tcp", "1024-65535", []string{"0.0.0.0/0"})}, compliancekit.StatusFail},
		{"wide-from-private", []godo.InboundRule{inbound("tcp", "1024-65535", []string{"10.0.0.0/8"})}, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFirewall(c.name, map[string]any{"inbound_rules": c.rules}, nil))
			findings, _ := FirewallBroadPortRange(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallOutboundDenyAll(t *testing.T) {
	cases := []struct {
		name  string
		rules []godo.OutboundRule
		want  compliancekit.Status
	}{
		{"any-to-any", []godo.OutboundRule{outbound("tcp", "all", []string{"0.0.0.0/0"})}, compliancekit.StatusFail},
		{"narrow-egress", []godo.OutboundRule{outbound("tcp", "443", []string{"0.0.0.0/0"})}, compliancekit.StatusPass},
		{"empty", []godo.OutboundRule{}, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFirewall(c.name, map[string]any{"outbound_rules": c.rules}, nil))
			findings, _ := FirewallOutboundDenyAll(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallOrphan(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		tags  []string
		want  compliancekit.Status
	}{
		{"has-droplets", map[string]any{"droplet_ids": []int{1, 2}}, nil, compliancekit.StatusPass},
		{"has-tags", map[string]any{"droplet_ids": []int{}}, []string{"web"}, compliancekit.StatusPass},
		{"orphan", map[string]any{"droplet_ids": []int{}}, nil, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFirewall(c.name, c.attrs, c.tags))
			findings, _ := FirewallOrphan(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}
