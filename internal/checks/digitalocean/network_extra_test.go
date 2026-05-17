package digitalocean

import (
	"context"
	"strings"
	"testing"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 7 — tests for the 10 networking-depth checks.

func mkFW(name string, inbound []godo.InboundRule, outbound []godo.OutboundRule) core.Resource {
	return core.Resource{
		ID:       "digitalocean.firewall." + name,
		Type:     docol.FirewallType,
		Name:     name,
		Provider: "digitalocean",
		Attributes: map[string]any{
			"inbound_rules":  inbound,
			"outbound_rules": outbound,
		},
	}
}

func mkVPCRegional(uuid, region string) core.Resource {
	return core.Resource{
		ID: "digitalocean.vpc." + uuid, Type: docol.VPCType, Name: uuid, Provider: "digitalocean",
		Attributes: map[string]any{"uuid": uuid, "region": region},
	}
}

func mkPeering(name string, vpcIDs []string) core.Resource {
	return core.Resource{
		ID: "digitalocean.vpc_peering." + name, Type: docol.VPCPeeringType, Name: name, Provider: "digitalocean",
		Attributes: map[string]any{"vpc_ids": vpcIDs},
	}
}

func mkLBExtra(name string, rules []map[string]any) core.Resource {
	return core.Resource{
		ID: "digitalocean.load_balancer." + name, Type: docol.LoadBalancerType, Name: name, Provider: "digitalocean",
		Attributes: map[string]any{"forwarding_rules": rules},
	}
}

func TestFWInboundDuplicates(t *testing.T) {
	dup := []godo.InboundRule{
		{Protocol: "tcp", PortRange: "443", Sources: &godo.Sources{Addresses: []string{"0.0.0.0/0"}}},
		{Protocol: "tcp", PortRange: "443", Sources: &godo.Sources{Addresses: []string{"0.0.0.0/0"}}},
	}
	uniq := []godo.InboundRule{
		{Protocol: "tcp", PortRange: "443", Sources: &godo.Sources{Addresses: []string{"0.0.0.0/0"}}},
		{Protocol: "tcp", PortRange: "22", Sources: &godo.Sources{Addresses: []string{"10.0.0.0/8"}}},
	}
	g := newAccountGraph(mkFW("dupe", dup, nil), mkFW("uniq", uniq, nil))
	findings, _ := FWInboundDuplicates(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["dupe"] != core.StatusFail || by["uniq"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestFWOutboundUnrestricted(t *testing.T) {
	g := newAccountGraph(
		mkFW("open", nil, nil),
		mkFW("restricted", nil, []godo.OutboundRule{{Protocol: "tcp", PortRange: "443"}}),
	)
	findings, _ := FWOutboundUnrestricted(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["open"] != core.StatusFail || by["restricted"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestFWICMPFromAny(t *testing.T) {
	open := []godo.InboundRule{{Protocol: "icmp", Sources: &godo.Sources{Addresses: []string{"0.0.0.0/0"}}}}
	tight := []godo.InboundRule{{Protocol: "icmp", Sources: &godo.Sources{Addresses: []string{"10.0.0.0/8"}}}}
	g := newAccountGraph(mkFW("open", open, nil), mkFW("tight", tight, nil))
	findings, _ := FWICMPFromAny(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["open"] != core.StatusFail || by["tight"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestVPCPeeringCrossRegion(t *testing.T) {
	g := newAccountGraph(
		mkVPCRegional("v1", "nyc3"), mkVPCRegional("v2", "sfo3"), mkVPCRegional("v3", "nyc3"),
		mkPeering("cross", []string{"v1", "v2"}),
		mkPeering("intra", []string{"v1", "v3"}),
	)
	findings, _ := VPCPeeringCrossRegion(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["cross"] != core.StatusFail || by["intra"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestReservedIPNoRegion(t *testing.T) {
	with := core.Resource{ID: "digitalocean.reserved_ip.a", Type: docol.ReservedIPType, Name: "1.2.3.4", Provider: "digitalocean", Region: "nyc3"}
	without := core.Resource{ID: "digitalocean.reserved_ip.b", Type: docol.ReservedIPType, Name: "5.6.7.8", Provider: "digitalocean"}
	g := newAccountGraph(with, without)
	findings, _ := ReservedIPNoRegion(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["1.2.3.4"] != core.StatusPass || by["5.6.7.8"] != core.StatusFail {
		t.Errorf("statuses=%+v", by)
	}
}

func TestLBTLSPassthroughWithoutHTTPS(t *testing.T) {
	badRules := []map[string]any{
		{"entry_protocol": "https", "target_protocol": "http", "tls_passthrough": true},
	}
	goodRules := []map[string]any{
		{"entry_protocol": "https", "target_protocol": "http", "tls_passthrough": false},
		{"entry_protocol": "https", "target_protocol": "https", "tls_passthrough": true},
	}
	g := newAccountGraph(mkLBExtra("bad", badRules), mkLBExtra("good", goodRules))
	findings, _ := LBTLSPassthroughWithoutHTTPS(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["bad"] != core.StatusFail || by["good"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestNetworkManualVerifyChecks(t *testing.T) {
	lb := mkLBExtra("lb", nil)
	cases := []struct {
		name string
		fn   func(context.Context, *core.ResourceGraph) ([]core.Finding, error)
		hint string
	}{
		{"sticky cookie", LBStickyCookieHTTPOnly, "Set-Cookie"},
		{"proxy protocol", LBProxyProtocol, "proxy"},
		{"ssl cipher", LBSSLCipherFloor, "ssllabs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), newAccountGraph(lb))
			if findings[0].Status != core.StatusError {
				t.Errorf("status=%v want StatusError", findings[0].Status)
			}
			if !strings.Contains(strings.ToLower(findings[0].Message), strings.ToLower(c.hint)) {
				t.Errorf("message %q missing %q", findings[0].Message, c.hint)
			}
		})
	}
}

func TestFWEmptyTagSource(t *testing.T) {
	withTag := mkFW("with-tag", []godo.InboundRule{
		{Protocol: "tcp", PortRange: "443", Sources: &godo.Sources{Tags: []string{"bastion"}}},
	}, nil)
	noTag := mkFW("no-tag", []godo.InboundRule{
		{Protocol: "tcp", PortRange: "443", Sources: &godo.Sources{Addresses: []string{"0.0.0.0/0"}}},
	}, nil)
	g := newAccountGraph(withTag, noTag)
	findings, _ := FWEmptyTagSource(context.Background(), g)
	// no-tag has no tag sources → no finding emitted
	if len(findings) != 1 {
		t.Fatalf("findings=%d want 1 (only with-tag firewall fires)", len(findings))
	}
	if findings[0].Status != core.StatusError {
		t.Errorf("status=%v want StatusError", findings[0].Status)
	}
}
