// Package digitalocean is the DigitalOcean Collector.
//
// It uses godo (the official DO SDK) to fetch resources via the v2 API
// and emits typed core.Resource values into the engine's ResourceGraph.
// See ARCHITECTURE.md §8 for the prioritized check list and CHECKS.md
// for how a check consumes the resources this collector produces.
//
// At v0.1 only droplets are fetched. Phase 5 adds firewalls (with
// droplet -> firewall edges so cross-resource checks work) plus the
// singleton account resource. Later versions add Spaces, databases,
// DOKS, load balancers, container registry, and VPCs.
package digitalocean

import (
	"context"
	"fmt"
	"net/url"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	providerName = "digitalocean"

	// pageSize is the per-page limit for paginated API calls. DO caps this
	// at 200; we use the max to minimize round trips on large accounts.
	pageSize = 200
)

// Collector fetches resources from a DigitalOcean account.
//
// Construct via New for production (token-based) or NewWithClient for
// tests (httptest-backed godo.Client). The zero value is not usable.
type Collector struct {
	client *godo.Client
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

// Collect fetches every supported resource type and emits a flat slice
// of core.Resource values. The engine adds them to a ResourceGraph and
// runs registered checks against it.
//
// A failure in any sub-collector aborts Collect -- partial data would
// produce misleading findings (e.g. "droplet has no firewall" when in
// fact firewalls just failed to list).
//
// After collection, droplet -> firewall edges are populated so
// cross-resource checks (no-firewall, ssh-from-any) can traverse the
// graph via ResourceGraph.Related without re-querying the API.
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	droplets, err := c.collectDroplets(ctx)
	if err != nil {
		return nil, fmt.Errorf("droplets: %w", err)
	}
	firewalls, err := c.collectFirewalls(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewalls: %w", err)
	}

	linkDropletsToFirewalls(droplets, firewalls)

	resources := make([]core.Resource, 0, len(droplets)+len(firewalls))
	resources = append(resources, droplets...)
	resources = append(resources, firewalls...)
	return resources, nil
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
