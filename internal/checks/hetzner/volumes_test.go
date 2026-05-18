package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkVolume(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "orphan" {
			want = compliancekit.StatusFail
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
		want := compliancekit.StatusPass
		if f.Resource.Name == "orphan-unfmt" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
