package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	// VolumeType is the resource type for block-storage volumes.
	VolumeType = "digitalocean.volume"

	// SnapshotType is the resource type for droplet + volume
	// snapshots.
	SnapshotType = "digitalocean.snapshot"
)

func (c *Collector) collectVolumes(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListVolumeParams{ListOptions: &godo.ListOptions{PerPage: pageSize}}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		volumes, resp, err := c.client.Storage.ListVolumes(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, v := range volumes {
			out = append(out, c.volumeResource(v))
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return out, fmt.Errorf("pagination: %w", err)
		}
		opt.ListOptions.Page = page + 1
	}
	return out, nil
}

func (c *Collector) volumeResource(v godo.Volume) core.Resource {
	region := ""
	if v.Region != nil {
		region = v.Region.Slug
	}
	dropletIDs := append([]int(nil), v.DropletIDs...)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", VolumeType, v.ID),
		Type:     VolumeType,
		Name:     v.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"volume_id":       v.ID,
			"size_gigabytes":  v.SizeGigaBytes,
			"droplet_ids":     dropletIDs,
			"created_at":      v.CreatedAt,
			"filesystem_type": v.FilesystemType,
		},
		Tags: v.Tags,
	}
	c.stamp(&r, region)
	return r
}

func (c *Collector) collectSnapshots(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		snaps, resp, err := c.client.Snapshots.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, s := range snaps {
			out = append(out, c.snapshotResource(s))
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return out, fmt.Errorf("pagination: %w", err)
		}
		opt.Page = page + 1
	}
	return out, nil
}

func (c *Collector) snapshotResource(s godo.Snapshot) core.Resource {
	regions := append([]string(nil), s.Regions...)
	primaryRegion := ""
	if len(regions) > 0 {
		primaryRegion = regions[0]
	}
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", SnapshotType, s.ID),
		Type:     SnapshotType,
		Name:     s.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"snapshot_id":    s.ID,
			"resource_id":    s.ResourceID,
			"resource_type":  s.ResourceType,
			"regions":        regions,
			"size_gigabytes": s.SizeGigaBytes,
			"min_disk_size":  s.MinDiskSize,
			"created_at":     s.Created,
		},
		Tags: s.Tags,
	}
	c.stamp(&r, primaryRegion)
	return r
}
