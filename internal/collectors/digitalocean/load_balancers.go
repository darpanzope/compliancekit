package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// LoadBalancerType is the resource type for DO Load Balancers.
const LoadBalancerType = "digitalocean.load_balancer"

// collectLoadBalancers enumerates every Load Balancer in the
// authenticated account with its forwarding rules + health check.
func (c *Collector) collectLoadBalancers(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		lbs, resp, err := c.client.LoadBalancers.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for i := range lbs {
			out = append(out, c.loadBalancerResource(&lbs[i]))
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

func (c *Collector) loadBalancerResource(lb *godo.LoadBalancer) core.Resource {
	region := ""
	if lb.Region != nil {
		region = lb.Region.Slug
	}

	rules := []map[string]any{}
	for _, fr := range lb.ForwardingRules {
		rules = append(rules, map[string]any{
			"entry_protocol":  fr.EntryProtocol,
			"entry_port":      fr.EntryPort,
			"target_protocol": fr.TargetProtocol,
			"target_port":     fr.TargetPort,
			"certificate_id":  fr.CertificateID,
			"tls_passthrough": fr.TlsPassthrough,
		})
	}

	hc := map[string]any{}
	if lb.HealthCheck != nil {
		hc["protocol"] = lb.HealthCheck.Protocol
		hc["port"] = lb.HealthCheck.Port
		hc["path"] = lb.HealthCheck.Path
	}

	dropletIDs := append([]int(nil), lb.DropletIDs...)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", LoadBalancerType, lb.ID),
		Type:     LoadBalancerType,
		Name:     lb.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"lb_id":                  lb.ID,
			"status":                 lb.Status,
			"algorithm":              lb.Algorithm,
			"size_slug":              lb.SizeSlug,
			"ip":                     lb.IP,
			"forwarding_rules":       rules,
			"health_check":           hc,
			"droplet_ids":            dropletIDs,
			"droplet_tag":            lb.Tag,
			"vpc_uuid":               lb.VPCUUID,
			"redirect_http_to_https": lb.RedirectHttpToHttps,
			"enable_proxy_protocol":  lb.EnableProxyProtocol,
		},
		Tags: nil,
	}
	c.stamp(&r, region)
	return r
}
