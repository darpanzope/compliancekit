package hetzner

import (
	"context"
	"testing"
	"time"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

func newGraphWith(resources ...core.Resource) *core.ResourceGraph {
	g := core.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g
}

func mkServer(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "hetzner.server." + name,
		Type:       hetznercol.ServerType,
		Name:       name,
		Provider:   "hetzner",
		Attributes: attrs,
	}
}

func TestServerBackups(t *testing.T) {
	g := newGraphWith(
		mkServer("on", map[string]any{"backup_window": "22-02"}),
		mkServer("off", map[string]any{"backup_window": ""}),
	)
	findings, _ := ServerBackups(context.Background(), g)
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

func TestServerRescueDisabled(t *testing.T) {
	g := newGraphWith(
		mkServer("normal", map[string]any{"rescue_enabled": false}),
		mkServer("rescue", map[string]any{"rescue_enabled": true}),
	)
	findings, _ := ServerRescueDisabled(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "rescue" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestServerImageAge(t *testing.T) {
	now := time.Now().UTC()
	g := newGraphWith(
		mkServer("fresh", map[string]any{"image_created": now.Add(-30 * 24 * time.Hour), "image_name": "ubuntu-24.04"}),
		mkServer("stale", map[string]any{"image_created": now.Add(-400 * 24 * time.Hour), "image_name": "ubuntu-22.04"}),
		mkServer("unknown", map[string]any{}),
	)
	findings, _ := ServerImageAge(context.Background(), g)
	for _, f := range findings {
		var want core.Status
		switch f.Resource.Name {
		case "fresh":
			want = core.StatusPass
		case "stale":
			want = core.StatusFail
		case "unknown":
			want = core.StatusSkip
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestServerStatusRunning(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   core.Status
	}{
		{"on", "running", core.StatusPass},
		{"off", "off", core.StatusFail},
		{"init", "initializing", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkServer(c.name, map[string]any{"status": c.status}))
			findings, _ := ServerStatusRunning(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestServerNotLocked(t *testing.T) {
	g := newGraphWith(
		mkServer("free", map[string]any{"locked": false}),
		mkServer("locked", map[string]any{"locked": true}),
	)
	findings, _ := ServerNotLocked(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "locked" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
