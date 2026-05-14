package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkVolume(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "hetzner.volume." + name,
		Type:       hetznercol.VolumeType,
		Name:       name,
		Provider:   "hetzner",
		Attributes: attrs,
	}
}

func TestVolumeOrphan(t *testing.T) {
	g := newGraphWith(
		mkVolume("attached", map[string]any{"attached": true}),
		mkVolume("orphan", map[string]any{"attached": false}),
	)
	findings, _ := VolumeOrphan(context.Background(), g)
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

func TestVolumeFormatted(t *testing.T) {
	g := newGraphWith(
		mkVolume("attached-fmt", map[string]any{"attached": true, "format": "ext4"}),
		mkVolume("attached-unfmt", map[string]any{"attached": true, "format": ""}),
		mkVolume("orphan-fmt", map[string]any{"attached": false, "format": "ext4"}),
		mkVolume("orphan-unfmt", map[string]any{"attached": false, "format": ""}),
	)
	findings, _ := VolumeFormatted(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "orphan-unfmt" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
