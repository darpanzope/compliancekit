package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// DatabaseType is the resource type for DO Managed Databases.
const DatabaseType = "digitalocean.database"

func (c *Collector) collectDatabases(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		dbs, resp, err := c.client.Databases.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for i := range dbs {
			out = append(out, c.databaseResource(ctx, &dbs[i]))
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

func (c *Collector) databaseResource(ctx context.Context, d *godo.Database) core.Resource {
	publicSSL := false
	publicHost := ""
	if d.Connection != nil {
		publicSSL = d.Connection.SSL
		publicHost = d.Connection.Host
	}
	privateHost := ""
	if d.PrivateConnection != nil {
		privateHost = d.PrivateConnection.Host
	}

	maintDay := ""
	maintHour := ""
	if d.MaintenanceWindow != nil {
		maintDay = d.MaintenanceWindow.Day
		maintHour = d.MaintenanceWindow.Hour
	}

	rules := c.fetchDBFirewall(ctx, d.ID)
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", DatabaseType, d.ID),
		Type:     DatabaseType,
		Name:     d.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"database_id":         d.ID,
			"engine":              d.EngineSlug,
			"version":             d.VersionSlug,
			"status":              d.Status,
			"num_nodes":           d.NumNodes,
			"size_slug":           d.SizeSlug,
			"vpc_uuid":            d.PrivateNetworkUUID,
			"public_host":         publicHost,
			"public_ssl":          publicSSL,
			"private_host":        privateHost,
			"maintenance_day":     maintDay,
			"maintenance_hour":    maintHour,
			"firewall_rules":      rules,
			"firewall_rule_count": len(rules),
		},
		Tags: d.Tags,
	}
	c.stamp(&r, d.RegionSlug)
	return r
}

// fetchDBFirewall pulls the per-database trusted-sources list.
// Returns a slice of {type, value} maps. On error returns nil so
// the parent emits the database resource without rules; the
// check renderer treats nil as "couldn't read."
func (c *Collector) fetchDBFirewall(ctx context.Context, dbID string) []map[string]any {
	fws, _, err := c.client.Databases.GetFirewallRules(ctx, dbID)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(fws))
	for _, fw := range fws {
		out = append(out, map[string]any{
			"type":  fw.Type,
			"value": fw.Value,
		})
	}
	return out
}
