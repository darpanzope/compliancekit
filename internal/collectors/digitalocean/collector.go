// Package digitalocean is the DigitalOcean Collector.
//
// It uses godo (the official DO SDK) to fetch resources via the v2 API
// and emits typed core.Resource values into the engine's ResourceGraph.
// See ARCHITECTURE.md §8 for the prioritized check list and CHECKS.md
// for how a check consumes the resources this collector produces.
//
// Authentication failures (the Account probe) abort the scan; per-
// service failures land as digitalocean.collect_error placeholders
// rather than aborting, so a single rate-limited or permission-
// denied service does not lose findings from the other 19. Same
// per-service-error pattern as AWS (v0.7) and GCP (v0.8).
package digitalocean

import (
	"context"
	"fmt"
	"net/url"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	providerName = "digitalocean"

	// pageSize is the per-page limit for paginated API calls. DO caps this
	// at 200; we use the max to minimize round trips on large accounts.
	pageSize = 200

	// CollectErrorType is the placeholder resource type emitted when a
	// per-service collector fails. Check code can opt-in to look at
	// these (or ignore them); the renderer surfaces the count in the
	// scan footer so the operator knows partial data was returned.
	CollectErrorType = "digitalocean.collect_error"
)

// Collector fetches resources from a DigitalOcean account.
//
// Construct via New for production (token-based) or NewWithClient for
// tests (httptest-backed godo.Client). The zero value is not usable.
type Collector struct {
	client *godo.Client

	// accountID is populated by the Account probe at the top of
	// Collect. Per-service helpers read it to stamp every resource
	// via cloudcommon.Stamp.
	accountID string
}

// New constructs a Collector authenticated with the given API token.
// Use NewWithClient to inject a pre-configured godo.Client (tests
// pointing at httptest.NewServer, or operators who want a custom
// transport with retry policy, etc.).
func New(token string) *Collector {
	return &Collector{client: godo.NewFromToken(token)}
}

// NewWithClient constructs a Collector around an existing godo.Client.
// Tests wire godo at an httptest.NewServer base URL via this entry point.
func NewWithClient(client *godo.Client) *Collector {
	return &Collector{client: client}
}

// Name returns the provider identifier.
func (c *Collector) Name() string { return providerName }

// Collect fetches every supported resource type and emits a flat
// slice of core.Resource values. The engine adds them to a
// ResourceGraph and runs registered checks against it.
//
// Order of operations:
//
//  1. Account probe. Failure here aborts the scan -- almost always
//     means auth is broken or the token has zero scope; running
//     other services would compound the noise.
//  2. Per-service collectors run sequentially. Each captures its
//     own errors as digitalocean.collect_error placeholders and
//     continues to the next service.
//  3. Cross-service edges (droplet -> firewall) are populated last.
//
// Sub-collectors return ([]core.Resource, error). When err != nil
// the helper still gets a chance to return any resources collected
// before the failure; the orchestrator adds them AND a placeholder
// so the check engine sees both.
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	account, accountResource, err := c.fetchAccount(ctx)
	if err != nil {
		return nil, err
	}
	c.accountID = stampAccountID(account)
	out := []core.Resource{accountResource}

	type result struct {
		service   string
		resources []core.Resource
		err       error
	}
	type subCollector struct {
		service string
		run     func(context.Context) ([]core.Resource, error)
	}
	subs := []subCollector{
		{"droplets", c.collectDroplets},
		{"firewalls", c.collectFirewalls},
		{"vpcs", c.collectVPCs},
		{"load_balancers", c.collectLoadBalancers},
		{"domains", c.collectDomains},
		{"certificates", c.collectCertificates},
		{"volumes", c.collectVolumes},
		{"snapshots", c.collectSnapshots},
		{"databases", c.collectDatabases},
		{"spaces", c.collectSpaces},
		{"spaces_keys", c.collectSpacesKeys},
		{"registry", c.collectRegistry},
		{"apps", c.collectApps},
		{"functions", c.collectFunctions},
		// Future phases add: cdn, reserved_ips, keys, images,
		// monitoring, projects.
	}

	// Run every sub-collector first so we can cross-link the
	// resulting slices in place before they are copied into out.
	results := make(map[string]result, len(subs))
	for _, s := range subs {
		r := result{service: s.service}
		r.resources, r.err = s.run(ctx)
		results[s.service] = r
	}

	// Populate droplet -> firewall edges. Slices are mutated in
	// place; this must happen before the copy into out.
	if d, ok := results["droplets"]; ok && d.err == nil {
		if fw, ok := results["firewalls"]; ok && fw.err == nil {
			linkDropletsToFirewalls(d.resources, fw.resources)
		}
	}

	for _, s := range subs {
		r := results[s.service]
		if r.err != nil {
			out = append(out, c.collectError(s.service, r.err))
			continue
		}
		out = append(out, r.resources...)
	}
	return out, nil
}

// collectError emits a placeholder when a per-service collector
// fails outright. Lets the scan continue with findings from other
// services while still surfacing the failure to the operator.
func (c *Collector) collectError(service string, err error) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", CollectErrorType, service),
		Type:     CollectErrorType,
		Name:     service,
		Provider: providerName,
		Attributes: map[string]any{
			"service": service,
			"error":   err.Error(),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.accountID})
	return r
}

// stamp is the per-resource helper every service collector should
// use after building a core.Resource so account_id is always set.
// Region is passed by the caller because it varies per resource
// (droplets are regional, account is global, etc.).
func (c *Collector) stamp(r *core.Resource, region string) {
	cloudcommon.Stamp(r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    region,
	})
}

// newClient is a test helper that returns a godo.Client whose BaseURL
// points at the given URL (typically an httptest.NewServer). The token
// is included but is ignored by fixture servers.
func newClient(token, baseURL string) (*godo.Client, error) {
	c := godo.NewFromToken(token)
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("parse baseURL: %w", err)
		}
		c.BaseURL = u
	}
	return c, nil
}
