package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// FloatingIPType is the resource type for Hetzner Cloud Floating
// IPs (the reserved-IP analog).
const FloatingIPType = "hetzner.floating_ip"

func (c *Collector) collectFloatingIPs(ctx context.Context) ([]core.Resource, error) {
	ips, err := c.client.FloatingIP.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Resource, 0, len(ips))
	for _, ip := range ips {
		out = append(out, c.floatingIPResource(ip))
	}
	return out, nil
}

func (c *Collector) floatingIPResource(ip *hcloud.FloatingIP) core.Resource {
	region := ""
	if ip.HomeLocation != nil {
		region = ip.HomeLocation.Name
	}
	addr := ""
	if ip.IP != nil {
		addr = ip.IP.String()
	}
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%d", FloatingIPType, ip.ID),
		Type:     FloatingIPType,
		Name:     ip.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"floating_ip_id": ip.ID,
			"address":        addr,
			"type":           string(ip.Type),
			"attached":       ip.Server != nil,
			"blocked":        ip.Blocked,
			"created_at":     ip.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.projectID,
		Region:    region,
	})
	return r
}
