package digitalocean

import (
	"context"
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
)

// FunctionsNamespaceType is the resource type for DO Functions
// namespaces. Functions are namespace-scoped; one resource per
// namespace with derived attributes summarizing trigger + access-
// key counts.
const FunctionsNamespaceType = "digitalocean.functions_namespace"

func (c *Collector) collectFunctions(ctx context.Context) ([]core.Resource, error) {
	namespaces, _, err := c.client.Functions.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	out := []core.Resource{}
	for _, ns := range namespaces {
		// best-effort trigger + key counts
		triggers, _, _ := c.client.Functions.ListTriggers(ctx, ns.Namespace)
		keys, _, _ := c.client.Functions.ListAccessKeys(ctx, ns.Namespace)

		enabledTriggers := 0
		scheduledTriggers := 0
		for _, t := range triggers {
			if t.IsEnabled {
				enabledTriggers++
			}
			if t.Type == "SCHEDULED" {
				scheduledTriggers++
			}
		}

		r := core.Resource{
			ID:       fmt.Sprintf("%s.%s", FunctionsNamespaceType, ns.UUID),
			Type:     FunctionsNamespaceType,
			Name:     ns.Label,
			Provider: providerName,
			Attributes: map[string]any{
				"namespace":               ns.Namespace,
				"uuid":                    ns.UUID,
				"label":                   ns.Label,
				"api_host":                ns.ApiHost,
				"trigger_count":           len(triggers),
				"enabled_trigger_count":   enabledTriggers,
				"scheduled_trigger_count": scheduledTriggers,
				"access_key_count":        len(keys),
			},
		}
		c.stamp(&r, ns.Region)
		out = append(out, r)
	}
	return out, nil
}
