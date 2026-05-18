package hetzner

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// FirewallType is the resource type for Hetzner Cloud firewalls.
// Hetzner firewalls are deny-by-default; an empty rules slice
// means "deny everything," not "allow everything."
const FirewallType = "hetzner.firewall"

func (c *Collector) collectFirewalls(ctx context.Context) ([]compliancekit.Resource, error) {
	firewalls, err := c.client.Firewall.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]compliancekit.Resource, 0, len(firewalls))
	for _, fw := range firewalls {
		out = append(out, c.firewallResource(fw))
	}
	return out, nil
}

func (c *Collector) firewallResource(fw *hcloud.Firewall) compliancekit.Resource {
	rules := []map[string]any{}
	for _, rule := range fw.Rules {
		sources := []string{}
		for _, n := range rule.SourceIPs {
			sources = append(sources, n.String())
		}
		dests := []string{}
		for _, n := range rule.DestinationIPs {
			dests = append(dests, n.String())
		}
		port := ""
		if rule.Port != nil {
			port = *rule.Port
		}
		rules = append(rules, map[string]any{
			"direction":       string(rule.Direction),
			"protocol":        string(rule.Protocol),
			"port":            port,
			"source_ips":      sources,
			"destination_ips": dests,
		})
	}

	applied := []map[string]any{}
	for _, t := range fw.AppliedTo {
		entry := map[string]any{
			"type": string(t.Type),
		}
		if t.Server != nil {
			entry["server_id"] = t.Server.ID
		}
		if t.LabelSelector != nil {
			entry["label_selector"] = t.LabelSelector.Selector
		}
		applied = append(applied, entry)
	}

	r := compliancekit.Resource{
		ID:       fmt.Sprintf("%s.%d", FirewallType, fw.ID),
		Type:     FirewallType,
		Name:     fw.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"firewall_id":   fw.ID,
			"rules":         rules,
			"applied_to":    applied,
			"applied_count": len(applied),
			"created_at":    fw.Created,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.projectID,
	})
	return r
}
