package hetzner

import (
	"context"
	"fmt"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ServerType is the resource type emitted per Hetzner Cloud
// server. Compute-level checks (backups, rescue mode, image age,
// status, lock) attach to this.
const ServerType = "hetzner.server"

func (c *Collector) collectServers(ctx context.Context) ([]core.Resource, error) {
	servers, err := c.client.Server.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Resource, 0, len(servers))
	for _, s := range servers {
		out = append(out, c.serverResource(s))
	}
	return out, nil
}

func (c *Collector) serverResource(s *hcloud.Server) core.Resource {
	region := ""
	if s.Location != nil {
		region = s.Location.Name
	}
	publicIPv4 := ""
	if !s.PublicNet.IPv4.IP.IsUnspecified() {
		publicIPv4 = s.PublicNet.IPv4.IP.String()
	}

	imageName := ""
	imageCreated := time.Time{}
	if s.Image != nil {
		imageName = s.Image.Name
		imageCreated = s.Image.Created
	}

	r := core.Resource{
		ID:       fmt.Sprintf("%s.%d", ServerType, s.ID),
		Type:     ServerType,
		Name:     s.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"server_id":         s.ID,
			"status":            string(s.Status),
			"public_ipv4":       publicIPv4,
			"backup_window":     s.BackupWindow,
			"rescue_enabled":    s.RescueEnabled,
			"locked":            s.Locked,
			"image_name":        imageName,
			"image_created":     imageCreated,
			"primary_disk_size": s.PrimaryDiskSize,
			"private_net_count": len(s.PrivateNet),
			"created_at":        s.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.projectID,
		Region:    region,
	})
	return r
}
