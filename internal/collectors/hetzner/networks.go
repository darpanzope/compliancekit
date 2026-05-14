package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// NetworkType is the resource type for Hetzner Cloud private
// networks. Hetzner Cloud uses a single VPC-like construct per
// project; there is no separate VPC/subnet distinction the way
// AWS has VPCs + subnets.
const NetworkType = "hetzner.network"

func (c *Collector) collectNetworks(ctx context.Context) ([]core.Resource, error) {
	nets, err := c.client.Network.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Resource, 0, len(nets))
	for _, n := range nets {
		out = append(out, c.networkResource(n))
	}
	return out, nil
}

func (c *Collector) networkResource(n *hcloud.Network) core.Resource {
	ipRange := ""
	if n.IPRange != nil {
		ipRange = n.IPRange.String()
	}
	subnets := []map[string]any{}
	for _, sub := range n.Subnets {
		sCidr := ""
		if sub.IPRange != nil {
			sCidr = sub.IPRange.String()
		}
		subnets = append(subnets, map[string]any{
			"type":         string(sub.Type),
			"ip_range":     sCidr,
			"network_zone": string(sub.NetworkZone),
			"gateway":      sub.Gateway.String(),
		})
	}

	r := core.Resource{
		ID:       fmt.Sprintf("%s.%d", NetworkType, n.ID),
		Type:     NetworkType,
		Name:     n.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"network_id":   n.ID,
			"ip_range":     ipRange,
			"subnet_count": len(n.Subnets),
			"subnets":      subnets,
			"server_count": len(n.Servers),
			"lb_count":     len(n.LoadBalancers),
			"member_count": len(n.Servers) + len(n.LoadBalancers),
			"created_at":   n.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.projectID})
	return r
}
