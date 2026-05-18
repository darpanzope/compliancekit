package digitalocean

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// RegistryType is the resource type for the DO Container Registry.
// DO Container Registry is a singleton per account: zero or one
// registry. The collector emits the resource only if a registry
// exists.
const RegistryType = "digitalocean.registry"

func (c *Collector) collectRegistry(ctx context.Context) ([]compliancekit.Resource, error) {
	reg, resp, err := c.client.Registry.Get(ctx)
	if err != nil {
		// 404 just means no registry on this account; treat as
		// zero resources, not an error.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	if reg == nil {
		return nil, nil
	}

	// Subscription tier (best-effort)
	tier := ""
	if sub, _, err := c.client.Registry.GetSubscription(ctx); err == nil && sub != nil && sub.Tier != nil {
		tier = sub.Tier.Slug
	}

	// Repository count (best-effort)
	repoCount := 0
	opts := &godo.ListOptions{PerPage: pageSize}
	repos, _, repoErr := c.client.Registry.ListRepositoriesV2(ctx, reg.Name, &godo.TokenListOptions{PerPage: opts.PerPage})
	if repoErr == nil {
		repoCount = len(repos)
	}

	// Last GC (best-effort)
	var lastGC any
	var lastGCStatus string
	if gc, _, gcErr := c.client.Registry.GetGarbageCollection(ctx, reg.Name); gcErr == nil && gc != nil {
		lastGC = gc.CreatedAt
		lastGCStatus = gc.Status
	} else if gcErr != nil && !errors.Is(gcErr, context.Canceled) {
		// 404 means no GC has been run; leave nil.
		lastGC = nil
	}

	r := compliancekit.Resource{
		ID:       fmt.Sprintf("%s.%s", RegistryType, reg.Name),
		Type:     RegistryType,
		Name:     reg.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"registry_name":       reg.Name,
			"storage_usage_bytes": reg.StorageUsageBytes,
			"subscription_tier":   tier,
			"repository_count":    repoCount,
			"last_gc_at":          lastGC,
			"last_gc_status":      lastGCStatus,
		},
	}
	c.stamp(&r, reg.Region)
	return []compliancekit.Resource{r}, nil
}
