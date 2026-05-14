package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkFloatingIP(name string, attached bool) core.Resource {
	return core.Resource{
		ID:       "hetzner.floating_ip." + name,
		Type:     hetznercol.FloatingIPType,
		Name:     name,
		Provider: "hetzner",
		Attributes: map[string]any{
			"attached": attached,
			"address":  "203.0.113.1",
		},
	}
}

func TestFloatingIPOrphan(t *testing.T) {
	g := newGraphWith(
		mkFloatingIP("attached", true),
		mkFloatingIP("orphan", false),
	)
	findings, _ := FloatingIPOrphan(context.Background(), g)
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
