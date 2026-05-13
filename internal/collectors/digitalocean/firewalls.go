package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// FirewallType is the core.Resource Type for firewall resources.
const FirewallType = "digitalocean.firewall"

// EdgeFirewall is the Relations key on a droplet pointing at its
// attached firewall resources. Cross-resource checks (no-firewall,
// ssh-from-any) traverse this edge via ResourceGraph.Related.
const EdgeFirewall = "firewall"

// collectFirewalls fetches every firewall in the authenticated account
// and maps each to a typed core.Resource. Pagination is handled
// internally; callers see a single flat slice.
func (c *Collector) collectFirewalls(ctx context.Context) ([]core.Resource, error) {
	var all []godo.Firewall
	opt := &godo.ListOptions{PerPage: pageSize}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		firewalls, resp, err := c.client.Firewalls.List(ctx, opt)
		if err != nil {
			return nil, err
		}
		all = append(all, firewalls...)

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
	for _, fw := range all {
		out = append(out, firewallToResource(fw))
	}
	return out, nil
}

// firewallToResource maps a godo.Firewall to a core.Resource.
//
// Attribute keys are part of the check contract; renaming one breaks
// every check that reads it.
func firewallToResource(fw godo.Firewall) core.Resource {
	return core.Resource{
		ID:       fmt.Sprintf("%s.%s", FirewallType, fw.ID),
		Type:     FirewallType,
		Name:     fw.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"status":         fw.Status,
			"inbound_rules":  fw.InboundRules,
			"outbound_rules": fw.OutboundRules,
			"droplet_ids":    fw.DropletIDs,
			"created_at":     fw.Created,
		},
		Tags: fw.Tags,
	}
}

// linkDropletsToFirewalls populates each droplet's Relations[EdgeFirewall]
// from the droplet_ids attribute of firewalls. Mutates droplets in place.
//
// This is the seam where the resource graph stops being a flat list and
// starts being an actual graph: a check can now ask "which firewalls
// protect this droplet?" via g.Related(droplet, EdgeFirewall) without
// re-querying the API or re-shaping the data.
func linkDropletsToFirewalls(droplets, firewalls []core.Resource) {
	// Build droplet ID -> []firewall ID index from the firewall side.
	dropletToFWs := map[string][]string{}
	for _, fw := range firewalls {
		ids, _ := fw.Attributes["droplet_ids"].([]int)
		for _, did := range ids {
			dropletResID := fmt.Sprintf("%s.%d", DropletType, did)
			dropletToFWs[dropletResID] = append(dropletToFWs[dropletResID], fw.ID)
		}
	}

	// Apply the edge to each droplet.
	for i := range droplets {
		if fws, ok := dropletToFWs[droplets[i].ID]; ok {
			if droplets[i].Relations == nil {
				droplets[i].Relations = make(map[string][]string)
			}
			droplets[i].Relations[EdgeFirewall] = fws
		}
	}
}
