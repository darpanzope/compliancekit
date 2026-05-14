package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// AppType is the resource type for App Platform applications.
const AppType = "digitalocean.app"

func (c *Collector) collectApps(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{}
	opt := &godo.ListOptions{PerPage: pageSize}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		apps, resp, err := c.client.Apps.List(ctx, opt)
		if err != nil {
			return out, err
		}
		for _, a := range apps {
			out = append(out, c.appResource(a))
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

func (c *Collector) appResource(a *godo.App) core.Resource {
	region := ""
	if a.Region != nil {
		region = a.Region.Slug
	}

	plainEnvCount := 0
	domains := []map[string]any{}
	hasAlerts := false
	hasVPC := a.VPC != nil

	if a.Spec != nil {
		for _, e := range a.Spec.Envs {
			if e.Type != godo.AppVariableType_Secret {
				plainEnvCount++
			}
		}
		for _, d := range a.Spec.Domains {
			domains = append(domains, map[string]any{
				"domain":              d.Domain,
				"type":                string(d.Type),
				"minimum_tls_version": d.MinimumTLSVersion,
			})
		}
		hasAlerts = len(a.Spec.Alerts) > 0
	}

	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", AppType, a.ID),
		Type:     AppType,
		Name:     a.Spec.GetName(),
		Provider: providerName,
		Attributes: map[string]any{
			"app_id":             a.ID,
			"tier_slug":          a.TierSlug,
			"live_url":           a.LiveURL,
			"live_domain":        a.LiveDomain,
			"plain_env_count":    plainEnvCount,
			"domains":            domains,
			"has_custom_domains": len(domains) > 0,
			"has_alerts":         hasAlerts,
			"in_vpc":             hasVPC,
		},
	}
	c.stamp(&r, region)
	return r
}
