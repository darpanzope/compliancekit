package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// LoadBalancerType is the resource type for Hetzner Cloud Load
// Balancers. TLS termination + HTTP/HTTPS redirect checks attach
// here.
const LoadBalancerType = "hetzner.load_balancer"

func (c *Collector) collectLoadBalancers(ctx context.Context) ([]core.Resource, error) {
	lbs, err := c.client.LoadBalancer.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Resource, 0, len(lbs))
	for _, lb := range lbs {
		out = append(out, c.loadBalancerResource(lb))
	}
	return out, nil
}

func (c *Collector) loadBalancerResource(lb *hcloud.LoadBalancer) core.Resource {
	region := ""
	if lb.Location != nil {
		region = lb.Location.Name
	}
	services := []map[string]any{}
	for _, s := range lb.Services {
		entry := map[string]any{
			"protocol":         string(s.Protocol),
			"listen_port":      s.ListenPort,
			"destination_port": s.DestinationPort,
			"redirect_http":    s.HTTP.RedirectHTTP,
			"cert_count":       len(s.HTTP.Certificates),
		}
		services = append(services, entry)
	}
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%d", LoadBalancerType, lb.ID),
		Type:     LoadBalancerType,
		Name:     lb.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"lb_id":        lb.ID,
			"algorithm":    string(lb.Algorithm.Type),
			"services":     services,
			"target_count": len(lb.Targets),
			"private_net":  len(lb.PrivateNet),
			"created_at":   lb.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.projectID,
		Region:    region,
	})
	return r
}
