package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// AppType is the resource type for App Platform applications.
const AppType = "digitalocean.app"

func (c *Collector) collectApps(ctx context.Context) ([]compliancekit.Resource, error) {
	out := []compliancekit.Resource{}
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

func (c *Collector) appResource(a *godo.App) compliancekit.Resource {
	region := ""
	if a.Region != nil {
		region = a.Region.Slug
	}

	plainEnvCount := 0
	domains := []map[string]any{}
	hasAlerts := false
	hasVPC := a.VPC != nil

	// v0.19 phase 5 — surface per-service hygiene attributes so the
	// new App-Platform depth checks can read them without re-issuing
	// the godo.Apps.Get call.
	serviceCount := 0
	servicesWithHealthcheck := 0
	servicesWithLogDest := 0
	servicesWithAlerts := 0
	servicesDeployOnPush := 0
	databaseCount := 0
	managedDBCount := 0

	if a.Spec != nil {
		plainEnvCount = appPlainEnvCount(a.Spec.Envs)
		domains = appDomainList(a.Spec.Domains)
		hasAlerts = len(a.Spec.Alerts) > 0
		serviceCount = len(a.Spec.Services)
		servicesWithHealthcheck, servicesWithLogDest, servicesWithAlerts, servicesDeployOnPush = appServiceSummary(a.Spec.Services)
		databaseCount = len(a.Spec.Databases)
		managedDBCount = appManagedDBCount(a.Spec.Databases)
	}

	r := compliancekit.Resource{
		ID:       fmt.Sprintf("%s.%s", AppType, a.ID),
		Type:     AppType,
		Name:     a.Spec.GetName(),
		Provider: providerName,
		Attributes: map[string]any{
			"app_id":                    a.ID,
			"tier_slug":                 a.TierSlug,
			"live_url":                  a.LiveURL,
			"live_domain":               a.LiveDomain,
			"plain_env_count":           plainEnvCount,
			"domains":                   domains,
			"has_custom_domains":        len(domains) > 0,
			"has_alerts":                hasAlerts,
			"in_vpc":                    hasVPC,
			"service_count":             serviceCount,
			"services_with_healthcheck": servicesWithHealthcheck,
			"services_with_log_dest":    servicesWithLogDest,
			"services_with_alerts":      servicesWithAlerts,
			"services_deploy_on_push":   servicesDeployOnPush,
			"database_count":            databaseCount,
			"managed_db_count":          managedDBCount,
		},
	}
	c.stamp(&r, region)
	return r
}

func appPlainEnvCount(envs []*godo.AppVariableDefinition) int {
	n := 0
	for _, e := range envs {
		if e.Type != godo.AppVariableType_Secret {
			n++
		}
	}
	return n
}

func appDomainList(domains []*godo.AppDomainSpec) []map[string]any {
	out := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		out = append(out, map[string]any{
			"domain":              d.Domain,
			"type":                string(d.Type),
			"minimum_tls_version": d.MinimumTLSVersion,
		})
	}
	return out
}

func appServiceSummary(services []*godo.AppServiceSpec) (healthcheck, logDest, alerts, deployOnPush int) {
	for _, s := range services {
		if s.HealthCheck != nil {
			healthcheck++
		}
		if len(s.LogDestinations) > 0 {
			logDest++
		}
		if len(s.Alerts) > 0 {
			alerts++
		}
		if s.Git != nil && s.Git.RepoCloneURL != "" {
			deployOnPush++
			continue
		}
		if s.GitHub != nil && s.GitHub.DeployOnPush {
			deployOnPush++
			continue
		}
		if s.GitLab != nil && s.GitLab.DeployOnPush {
			deployOnPush++
		}
	}
	return healthcheck, logDest, alerts, deployOnPush
}

func appManagedDBCount(dbs []*godo.AppDatabaseSpec) int {
	n := 0
	for _, db := range dbs {
		if db.Production {
			n++
		}
	}
	return n
}
