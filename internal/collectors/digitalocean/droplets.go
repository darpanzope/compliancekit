package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// DropletType is the core.Resource Type for droplet resources.
// Exported so check packages can reference it without hard-coding.
const DropletType = "digitalocean.droplet"

// collectDroplets fetches every droplet in the authenticated account
// and maps each to a typed core.Resource. Pagination is handled
// internally; callers see a single flat slice.
func (c *Collector) collectDroplets(ctx context.Context) ([]core.Resource, error) {
	var all []godo.Droplet
	opt := &godo.ListOptions{PerPage: pageSize}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		droplets, resp, err := c.client.Droplets.List(ctx, opt)
		if err != nil {
			return nil, err
		}
		all = append(all, droplets...)

		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, fmt.Errorf("pagination: %w", err)
		}
		opt.Page = page + 1
	}

	out := make([]core.Resource, 0, len(all))
	for _, d := range all {
		out = append(out, dropletToResource(d))
	}
	return out, nil
}

// dropletToResource maps a godo.Droplet to a core.Resource.
//
// Attribute keys are part of the check contract -- renaming one breaks
// every check that reads it. The set documented in CHECKS.md is
// authoritative; this function must keep parity.
func dropletToResource(d godo.Droplet) core.Resource {
	attrs := map[string]any{
		"status":      d.Status,
		"memory":      d.Memory,
		"vcpus":       d.Vcpus,
		"disk":        d.Disk,
		"size_slug":   d.SizeSlug,
		"features":    d.Features,
		"vpc_uuid":    d.VPCUUID,
		"created_at":  d.Created,
		"public_ipv4": publicIPv4(d),
	}
	if d.Image != nil {
		attrs["image_slug"] = d.Image.Slug
		attrs["image_distro"] = d.Image.Distribution
		attrs["image_created_at"] = d.Image.Created
	}

	region := ""
	if d.Region != nil {
		region = d.Region.Slug
	}

	return core.Resource{
		ID:         fmt.Sprintf("%s.%d", DropletType, d.ID),
		Type:       DropletType,
		Name:       d.Name,
		Provider:   providerName,
		Region:     region,
		Attributes: attrs,
		Tags:       d.Tags,
	}
}

// publicIPv4 returns the first public IPv4 address attached to the
// droplet, or "" if none. Checks like "droplet without firewall" only
// care about public-routable droplets.
func publicIPv4(d godo.Droplet) string {
	if d.Networks == nil {
		return ""
	}
	for _, n := range d.Networks.V4 {
		if n.Type == "public" {
			return n.IPAddress
		}
	}
	return ""
}
