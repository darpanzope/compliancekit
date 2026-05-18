package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkVolume(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.volume." + name,
		Type:       docol.VolumeType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func mkSnapshot(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.snapshot." + name,
		Type:       docol.SnapshotType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestVolumeOrphan(t *testing.T) {
	g := newAccountGraph(
		mkVolume("attached", map[string]any{"droplet_ids": []int{1}}),
		mkVolume("orphan", map[string]any{"droplet_ids": []int{}}),
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

func TestVolumeUnformattedOrphan(t *testing.T) {
	g := newAccountGraph(
		mkVolume("attached-formatted", map[string]any{"droplet_ids": []int{1}, "filesystem_type": "ext4"}),
		mkVolume("attached-unformatted", map[string]any{"droplet_ids": []int{1}, "filesystem_type": ""}),
		mkVolume("orphan-formatted", map[string]any{"droplet_ids": []int{}, "filesystem_type": "ext4"}),
		mkVolume("orphan-unformatted", map[string]any{"droplet_ids": []int{}, "filesystem_type": ""}),
	)
	findings, _ := VolumeUnformattedOrphan(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "orphan-unformatted" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSnapshotAge(t *testing.T) {
	now := time.Now().UTC()
	g := newAccountGraph(
		mkSnapshot("recent", map[string]any{"created_at": now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)}),
		mkSnapshot("old", map[string]any{"created_at": now.Add(-400 * 24 * time.Hour).Format(time.RFC3339)}),
		mkSnapshot("unparsable", map[string]any{"created_at": "junk"}),
	)
	findings, _ := SnapshotAge(context.Background(), g)
	for _, f := range findings {
		var want compliancekit.Status
		switch f.Resource.Name {
		case "recent":
			want = compliancekit.StatusPass
		case "old":
			want = compliancekit.StatusFail
		case "unparsable":
			want = compliancekit.StatusSkip
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSnapshotResourceExists(t *testing.T) {
	g := newAccountGraph(
		mkDroplet("d", map[string]any{}),
		mkVolume("v", map[string]any{}),
		mkSnapshot("good-droplet", map[string]any{"resource_type": "droplet", "resource_id": "d"}),
		mkSnapshot("orphan-droplet", map[string]any{"resource_type": "droplet", "resource_id": "gone"}),
		mkSnapshot("good-volume", map[string]any{"resource_type": "volume", "resource_id": "v"}),
		mkSnapshot("weird", map[string]any{"resource_type": "k8s_cluster", "resource_id": "x"}),
	)
	findings, _ := SnapshotResourceExists(context.Background(), g)
	for _, f := range findings {
		var want compliancekit.Status
		switch f.Resource.Name {
		case "good-droplet", "good-volume":
			want = compliancekit.StatusPass
		case "orphan-droplet":
			want = compliancekit.StatusFail
		case "weird":
			want = compliancekit.StatusSkip
		}
		if f.Status != want {
			t.Errorf("%s: got %v: %s", f.Resource.Name, f.Status, f.Message)
		}
	}
}
