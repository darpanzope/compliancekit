package hetzner

import (
	"context"
	"testing"
	"time"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func newGraphWith(resources ...compliancekit.Resource) *compliancekit.ResourceGraph {
	g := compliancekit.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g
}

func mkServer(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "off" {
			want = compliancekit.StatusFail
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "rescue" {
			want = compliancekit.StatusFail
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
		var want compliancekit.Status
		switch f.Resource.Name {
		case "fresh":
			want = compliancekit.StatusPass
		case "stale":
			want = compliancekit.StatusFail
		case "unknown":
			want = compliancekit.StatusSkip
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
		want   compliancekit.Status
	}{
		{"on", "running", compliancekit.StatusPass},
		{"off", "off", compliancekit.StatusFail},
		{"init", "initializing", compliancekit.StatusFail},
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "locked" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
