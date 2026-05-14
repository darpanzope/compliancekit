package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	// VPCType is the resource type for DO VPC networks.
	VPCType = "digitalocean.vpc"

	// VPCPeeringType is the resource type for inter-VPC peering
	// connections.
	VPCPeeringType = "digitalocean.vpc_peering"
)

// collectVPCs enumerates every VPC + every VPC peering in the
// authenticated account. Pagination handled internally; callers
// see one flat slice. Peering listing failures are swallowed
// (some accounts can't see them) so VPCs still ship.
func (c *Collector) collectVPCs(ctx context.Context) ([]core.Resource, error) {
	out, err := c.collectVPCsInner(ctx)
	if err != nil {
		return out, err
	}
	// Peering listing is best-effort.
	peerings, peerErr := c.listVPCPeerings(ctx)
	if peerErr == nil {
		out = append(out, peerings...)
	}
	return out, nil
}

func (c *Collector) collectVPCsInner(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		vpcs, resp, err := c.client.VPCs.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, v := range vpcs {
			out = append(out, c.vpcResource(ctx, v))
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

func (c *Collector) listVPCPeerings(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		peerings, resp, err := c.client.VPCs.ListVPCPeerings(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, p := range peerings {
			out = append(out, c.vpcPeeringResource(p))
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

// vpcResource maps a godo.VPC to a core.Resource. Tries to
// resolve the member count; falls back to zero if the
// per-VPC members call fails (e.g. permission denied).
func (c *Collector) vpcResource(ctx context.Context, v *godo.VPC) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", VPCType, v.ID),
		Type:     VPCType,
		Name:     v.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"vpc_id":       v.ID,
			"description":  v.Description,
			"ip_range":     v.IPRange,
			"is_default":   v.Default,
			"urn":          v.URN,
			"member_count": resolveVPCMembers(ctx, c.client, v.ID),
		},
	}
	c.stamp(&r, v.RegionSlug)
	return r
}

// resolveVPCMembers queries the per-VPC members list. Best-effort:
// returns 0 when the API call fails (permission denied, rate-
// limited, etc.); the orphan check accepts this as a fail-soft.
func resolveVPCMembers(ctx context.Context, client *godo.Client, vpcID string) int {
	members, _, err := client.VPCs.ListMembers(ctx, vpcID, &godo.VPCListMembersRequest{}, nil)
	if err != nil {
		return -1
	}
	return len(members)
}

func (c *Collector) vpcPeeringResource(p *godo.VPCPeering) core.Resource {
	vpcIDs := append([]string(nil), p.VPCIDs...)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", VPCPeeringType, p.ID),
		Type:     VPCPeeringType,
		Name:     p.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"peering_id": p.ID,
			"status":     p.Status,
			"vpc_ids":    vpcIDs,
		},
	}
	c.stamp(&r, "")
	return r
}
