package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// VolumeType is the resource type for Hetzner Cloud Block
// Storage Volumes.
const VolumeType = "hetzner.volume"

func (c *Collector) collectVolumes(ctx context.Context) ([]core.Resource, error) {
	vols, err := c.client.Volume.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Resource, 0, len(vols))
	for _, v := range vols {
		out = append(out, c.volumeResource(v))
	}
	return out, nil
}

func (c *Collector) volumeResource(v *hcloud.Volume) core.Resource {
	region := ""
	if v.Location != nil {
		region = v.Location.Name
	}
	format := ""
	if v.Format != nil {
		format = *v.Format
	}
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%d", VolumeType, v.ID),
		Type:     VolumeType,
		Name:     v.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"volume_id":  v.ID,
			"status":     string(v.Status),
			"attached":   v.Server != nil,
			"size_gb":    v.Size,
			"format":     format,
			"created_at": v.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.projectID,
		Region:    region,
	})
	return r
}
