// Package hetzner is the Hetzner Cloud Collector.
//
// It uses the official hcloud-go/v2 SDK to fetch resources via the
// Hetzner Cloud API and emits typed core.Resource values into the
// engine's ResourceGraph. See ROADMAP.md § v0.10 for the per-service
// check breakdown.
//
// Authentication is a single token (HCLOUD_TOKEN env var by default,
// override via providers.hetzner.token_env in the config). The token
// is project-scoped — one token == one Hetzner project; multi-
// project operators run multiple scans with different tokens.
//
// Authentication failure aborts the scan; per-service failures land
// as hetzner.collect_error placeholders rather than aborting, so a
// single rate-limited service doesn't lose findings from the rest.
// Same pattern as AWS (v0.7), GCP (v0.8), and DO (v0.9).
package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	providerName = "hetzner"

	// ProjectType is the singleton account/project anchor resource.
	// Hetzner has no separate organization surface (the token *is*
	// the project), so every scan emits exactly one of these.
	// Cross-cutting account-level checks attach here.
	ProjectType = "hetzner.project"

	// CollectErrorType is the placeholder resource type emitted
	// when a per-service collector fails. Check code can opt-in
	// to look at these; the renderer surfaces the count in the
	// scan footer so the operator knows partial data was returned.
	CollectErrorType = "hetzner.collect_error"
)

// Collector fetches resources from a Hetzner Cloud project.
//
// Construct via New for production (token-based) or NewWithClient
// for tests. The zero value is not usable.
type Collector struct {
	client *hcloud.Client

	// projectID is a stable identifier for the project. Hetzner
	// doesn't surface a numeric project ID via the API; we use
	// the token's first 8 chars as a fingerprint so the
	// cloudcommon.AccountID column is consistent across runs
	// without leaking the full token.
	projectID string
}

// New constructs a Collector authenticated with the given API
// token. The token is project-scoped on Hetzner; one token = one
// project. To scan multiple projects, run multiple scans with
// different tokens.
func New(token string) *Collector {
	return &Collector{
		client:    hcloud.NewClient(hcloud.WithToken(token)),
		projectID: projectFingerprint(token),
	}
}

// NewWithClient constructs a Collector around an existing
// hcloud.Client. Tests wire a fake client via this entry point.
func NewWithClient(client *hcloud.Client, projectID string) *Collector {
	return &Collector{client: client, projectID: projectID}
}

// Name returns the provider identifier.
func (c *Collector) Name() string { return providerName }

// projectFingerprint returns a stable, non-secret identifier for
// the token. First 8 chars is unique enough across an operator's
// token set without round-tripping any sensitive bytes into the
// evidence pack.
func projectFingerprint(token string) string {
	if len(token) < 8 {
		return "hetzner-project"
	}
	return "hetzner-" + token[:8]
}

// Collect fetches every supported resource type and emits a flat
// slice of core.Resource values.
//
// Order of operations:
//
//  1. Emit the project anchor first. Cheap and cannot fail.
//  2. Run per-service collectors sequentially. Each captures its
//     own errors as hetzner.collect_error placeholders and
//     continues to the next service.
func (c *Collector) Collect(ctx context.Context) ([]core.Resource, error) {
	out := []core.Resource{c.projectResource()}

	type subCollector struct {
		service string
		run     func(context.Context) ([]core.Resource, error)
	}
	subs := []subCollector{
		{"servers", c.collectServers},
		{"firewalls", c.collectFirewalls},
		{"networks", c.collectNetworks},
		// Phase 5+ adds: load_balancers, volumes, floating_ips.
	}

	for _, s := range subs {
		partial, err := s.run(ctx)
		if err != nil {
			out = append(out, c.collectError(s.service, err))
			continue
		}
		out = append(out, partial...)
	}
	return out, nil
}

// projectResource emits the singleton anchor. Account-level
// checks (none today, room for billing-alerts / quota-headroom
// later) attach here.
func (c *Collector) projectResource() core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("%s.%s", ProjectType, c.projectID),
		Type:     ProjectType,
		Name:     c.projectID,
		Provider: providerName,
		Attributes: map[string]any{
			"project_id": c.projectID,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.projectID})
	return r
}

// collectError emits a placeholder when a per-service collector
// fails outright.
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
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.projectID})
	return r
}

// stamp lands in phase 2 alongside the first service collector
// that needs it. Kept inline at the call site for now to avoid
// an unused-helper lint warning before the per-service files
// land.
