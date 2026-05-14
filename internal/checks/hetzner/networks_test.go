package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkNetwork(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "hetzner.network." + name,
		Type:       hetznercol.NetworkType,
		Name:       name,
		Provider:   "hetzner",
		Attributes: attrs,
	}
}

func TestNetworkOrphan(t *testing.T) {
	g := newGraphWith(
		mkNetwork("active", map[string]any{"member_count": 3, "ip_range": "10.0.0.0/16"}),
		mkNetwork("empty", map[string]any{"member_count": 0, "ip_range": "10.1.0.0/16"}),
	)
	findings, _ := NetworkOrphan(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "empty" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestNetworkRFC1918(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		want core.Status
	}{
		{"10-range", "10.0.0.0/16", core.StatusPass},
		{"172-private", "172.20.0.0/16", core.StatusPass},
		{"192-168", "192.168.0.0/16", core.StatusPass},
		{"public", "1.2.3.0/24", core.StatusFail},
		{"172-public", "172.32.0.0/16", core.StatusFail},
		{"empty", "", core.StatusSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkNetwork(c.name, map[string]any{"ip_range": c.cidr}))
			findings, _ := NetworkRFC1918(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}
