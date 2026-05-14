package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	ComputeInstanceType = "gcp.compute.instance"
	ComputeNetworkType  = "gcp.compute.network"
	ComputeFirewallType = "gcp.compute.firewall"

	// ComputeProjectType holds project-level metadata (OS Login,
	// SSH key project policy) that the checks read once per
	// project. One instance per scanned project.
	ComputeProjectType = "gcp.compute.project_metadata"
)

// collectCompute enumerates instances (across all zones),
// networks, firewalls, and project metadata for each project.
// Per-project errors emit a placeholder and continue to the next
// project.
func (c *Collector) collectCompute(ctx context.Context, out []core.Resource) []core.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectComputeForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "compute", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectComputeForProject(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	var err error
	if out, err = c.collectComputeInstances(ctx, projectID, out); err != nil {
		return out, fmt.Errorf("compute %s: %w", projectID, err)
	}
	if out, err = c.collectComputeNetworks(ctx, projectID, out); err != nil {
		return out, fmt.Errorf("compute %s: %w", projectID, err)
	}
	if out, err = c.collectComputeFirewalls(ctx, projectID, out); err != nil {
		return out, fmt.Errorf("compute %s: %w", projectID, err)
	}
	if out, err = c.collectComputeProjectMetadata(ctx, projectID, out); err != nil {
		return out, fmt.Errorf("compute %s: %w", projectID, err)
	}
	return out, nil
}

func (c *Collector) collectComputeInstances(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := compute.NewInstancesRESTClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new instances client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// AggregatedList returns instances across all zones in one call.
	it := client.AggregatedList(ctx, &computepb.AggregatedListInstancesRequest{Project: projectID})
	for {
		pair, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("aggregated list instances: %w", err)
		}
		if pair.Value == nil {
			continue
		}
		for _, inst := range pair.Value.Instances {
			out = append(out, c.computeInstanceResource(projectID, inst))
		}
	}
	return out, nil
}

func (c *Collector) computeInstanceResource(projectID string, inst *computepb.Instance) core.Resource {
	name := safeString(inst.Name)
	zone := lastPathSegment(safeString(inst.Zone))
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.compute.instance.%s.%s.%s", projectID, zone, name),
		Type:     ComputeInstanceType,
		Name:     name,
		Provider: providerName,
		Attributes: map[string]any{
			"instance_id":                   safeUint64(inst.Id),
			"zone":                          zone,
			"machine_type":                  lastPathSegment(safeString(inst.MachineType)),
			"status":                        safeString(inst.Status),
			"shielded_secure_boot":          shieldedAttr(inst, "EnableSecureBoot"),
			"shielded_vtpm":                 shieldedAttr(inst, "EnableVtpm"),
			"shielded_integrity_monitoring": shieldedAttr(inst, "EnableIntegrityMonitoring"),
			"service_accounts":              serviceAccountsToMaps(inst.ServiceAccounts),
			"metadata":                      metadataToMap(inst.Metadata),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    zone, // GCE instances are zonal; surface the zone as the "region" coord
	})
	return r
}

func shieldedAttr(inst *computepb.Instance, fieldName string) bool {
	if inst.ShieldedInstanceConfig == nil {
		return false
	}
	switch fieldName {
	case "EnableSecureBoot":
		return safeBool(inst.ShieldedInstanceConfig.EnableSecureBoot)
	case "EnableVtpm":
		return safeBool(inst.ShieldedInstanceConfig.EnableVtpm)
	case "EnableIntegrityMonitoring":
		return safeBool(inst.ShieldedInstanceConfig.EnableIntegrityMonitoring)
	}
	return false
}

func serviceAccountsToMaps(sas []*computepb.ServiceAccount) []map[string]any {
	out := make([]map[string]any, 0, len(sas))
	for _, sa := range sas {
		scopes := make([]string, 0, len(sa.Scopes))
		scopes = append(scopes, sa.Scopes...)
		out = append(out, map[string]any{
			"email":  safeString(sa.Email),
			"scopes": scopes,
		})
	}
	return out
}

func metadataToMap(md *computepb.Metadata) map[string]string {
	out := map[string]string{}
	if md == nil {
		return out
	}
	for _, item := range md.Items {
		key := safeString(item.Key)
		val := safeString(item.Value)
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func (c *Collector) collectComputeNetworks(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := compute.NewNetworksRESTClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new networks client: %w", err)
	}
	defer func() { _ = client.Close() }()

	it := client.List(ctx, &computepb.ListNetworksRequest{Project: projectID})
	for {
		n, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list networks: %w", err)
		}
		name := safeString(n.Name)
		r := core.Resource{
			ID:       fmt.Sprintf("gcp.compute.network.%s.%s", projectID, name),
			Type:     ComputeNetworkType,
			Name:     name,
			Provider: providerName,
			Attributes: map[string]any{
				"network_name": name,
				"is_default":   name == "default",
				"auto_create":  safeBool(n.AutoCreateSubnetworks),
				"description":  safeString(n.Description),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
		out = append(out, r)
	}
	return out, nil
}

func (c *Collector) collectComputeFirewalls(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := compute.NewFirewallsRESTClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new firewalls client: %w", err)
	}
	defer func() { _ = client.Close() }()

	it := client.List(ctx, &computepb.ListFirewallsRequest{Project: projectID})
	for {
		fw, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list firewalls: %w", err)
		}
		name := safeString(fw.Name)
		allowed := []map[string]any{}
		for _, a := range fw.Allowed {
			ports := append([]string(nil), a.Ports...)
			allowed = append(allowed, map[string]any{
				"protocol": safeString(a.IPProtocol),
				"ports":    ports,
			})
		}
		sourceRanges := append([]string(nil), fw.SourceRanges...)
		r := core.Resource{
			ID:       fmt.Sprintf("gcp.compute.firewall.%s.%s", projectID, name),
			Type:     ComputeFirewallType,
			Name:     name,
			Provider: providerName,
			Attributes: map[string]any{
				"firewall_name": name,
				"direction":     safeString(fw.Direction),
				"disabled":      safeBool(fw.Disabled),
				"source_ranges": sourceRanges,
				"allowed":       allowed,
				"network":       lastPathSegment(safeString(fw.Network)),
				"open_to_any":   contains(sourceRanges, "0.0.0.0/0"),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
		out = append(out, r)
	}
	return out, nil
}

func (c *Collector) collectComputeProjectMetadata(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := compute.NewProjectsRESTClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new projects client: %w", err)
	}
	defer func() { _ = client.Close() }()

	proj, err := client.Get(ctx, &computepb.GetProjectRequest{Project: projectID})
	if err != nil {
		return out, fmt.Errorf("get project metadata: %w", err)
	}
	osLogin := false
	for _, item := range proj.CommonInstanceMetadata.Items {
		if safeString(item.Key) == "enable-oslogin" && strings.EqualFold(safeString(item.Value), "TRUE") {
			osLogin = true
		}
	}
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.compute.project_metadata.%s", projectID),
		Type:     ComputeProjectType,
		Name:     projectID,
		Provider: providerName,
		Attributes: map[string]any{
			"os_login_enabled": osLogin,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
	out = append(out, r)
	return out, nil
}

func safeUint64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func safeString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func safeBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
