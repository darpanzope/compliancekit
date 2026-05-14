package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkFirewall(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "hetzner.firewall." + name,
		Type:       hetznercol.FirewallType,
		Name:       name,
		Provider:   "hetzner",
		Attributes: attrs,
	}
}

func TestFirewallSSHFromAny(t *testing.T) {
	cases := []struct {
		name  string
		rules []map[string]any
		want  core.Status
	}{
		{"ssh-from-any-ipv4", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "22", "source_ips": []string{"0.0.0.0/0"}},
		}, core.StatusFail},
		{"ssh-from-any-ipv6", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "22", "source_ips": []string{"::/0"}},
		}, core.StatusFail},
		{"ssh-from-bastion", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "22", "source_ips": []string{"203.0.113.0/24"}},
		}, core.StatusPass},
		{"no-ssh-rule", []map[string]any{}, core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkFirewall(c.name, map[string]any{"rules": c.rules, "applied_count": 1}))
			findings, _ := FirewallSSHFromAny(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallAnyFromAny(t *testing.T) {
	cases := []struct {
		name  string
		rules []map[string]any
		want  core.Status
	}{
		{"any-port-from-any-no-port", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "", "source_ips": []string{"0.0.0.0/0"}},
		}, core.StatusFail},
		{"any-port-from-any-full-range", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "1-65535", "source_ips": []string{"0.0.0.0/0"}},
		}, core.StatusFail},
		{"any-port-from-private", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "", "source_ips": []string{"10.0.0.0/8"}},
		}, core.StatusPass},
		{"narrow-from-public", []map[string]any{
			{"direction": "in", "protocol": "tcp", "port": "443", "source_ips": []string{"0.0.0.0/0"}},
		}, core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkFirewall(c.name, map[string]any{"rules": c.rules, "applied_count": 1}))
			findings, _ := FirewallAnyFromAny(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestFirewallOrphan(t *testing.T) {
	g := newGraphWith(
		mkFirewall("applied", map[string]any{"applied_count": 2, "rules": []map[string]any{}}),
		mkFirewall("orphan", map[string]any{"applied_count": 0, "rules": []map[string]any{}}),
	)
	findings, _ := FirewallOrphan(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "orphan" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
