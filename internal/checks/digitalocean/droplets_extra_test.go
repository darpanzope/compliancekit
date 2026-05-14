package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkDroplet(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.droplet." + name,
		Type:       docol.DropletType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestDropletMonitoring(t *testing.T) {
	g := newAccountGraph(
		mkDroplet("on", map[string]any{"features": []string{"monitoring", "private_networking"}}),
		mkDroplet("off", map[string]any{"features": []string{"private_networking"}}),
	)
	findings, _ := DropletMonitoring(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "off" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDropletInVPC(t *testing.T) {
	g := newAccountGraph(
		mkDroplet("vpc", map[string]any{"vpc_uuid": "vpc-123"}),
		mkDroplet("legacy", map[string]any{"vpc_uuid": ""}),
	)
	findings, _ := DropletInVPC(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "legacy" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDropletPrivateNetworking(t *testing.T) {
	g := newAccountGraph(
		mkDroplet("on", map[string]any{"features": []string{"private_networking"}}),
		mkDroplet("off", map[string]any{"features": []string{}}),
	)
	findings, _ := DropletPrivateNetworking(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "off" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestDropletStatusActive(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   core.Status
	}{
		{"active", "active", core.StatusPass},
		{"off", "off", core.StatusFail},
		{"archived", "archived", core.StatusFail},
		{"new", "new", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkDroplet(c.name, map[string]any{"status": c.status}))
			findings, _ := DropletStatusActive(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}
