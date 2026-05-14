package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	"github.com/darpanzope/compliancekit/internal/core"
)

// DOKS resource types. v0.11 holds back DOKS from v0.9 specifically
// so it can land alongside the K8s posture arc here.
const (
	DOKSClusterType  = "digitalocean.doks.cluster"
	DOKSNodePoolType = "digitalocean.doks.nodepool"
)

// collectDOKS enumerates DOKS clusters and their node pools.
func (c *Collector) collectDOKS(ctx context.Context) ([]core.Resource, error) {
	clusters, err := listAllDOKSClusters(ctx, c.client)
	if err != nil {
		return nil, fmt.Errorf("list doks clusters: %w", err)
	}
	out := make([]core.Resource, 0, len(clusters))
	for i := range clusters {
		cl := &clusters[i]
		out = append(out, c.doksClusterResource(cl))
		for j := range cl.NodePools {
			np := cl.NodePools[j]
			out = append(out, c.doksNodePoolResource(cl, np))
		}
	}
	return out, nil
}

func listAllDOKSClusters(ctx context.Context, client *godo.Client) ([]godo.KubernetesCluster, error) {
	all := []godo.KubernetesCluster{}
	opt := &godo.ListOptions{PerPage: 200}
	for {
		clusters, resp, err := client.Kubernetes.List(ctx, opt)
		if err != nil {
			return nil, err
		}
		for _, cl := range clusters {
			if cl != nil {
				all = append(all, *cl)
			}
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, perr := resp.Links.CurrentPage()
		if perr != nil {
			return nil, perr
		}
		opt.Page = page + 1
	}
	return all, nil
}

func (c *Collector) doksClusterResource(cl *godo.KubernetesCluster) core.Resource {
	status := ""
	if cl.Status != nil {
		status = string(cl.Status.State)
	}
	mw := ""
	if cl.MaintenancePolicy != nil {
		mw = fmt.Sprintf("%s %s", cl.MaintenancePolicy.Day, cl.MaintenancePolicy.StartTime)
	}
	attrs := map[string]any{
		"region":              cl.RegionSlug,
		"version":             cl.VersionSlug,
		"status":              status,
		"vpc_uuid":            cl.VPCUUID,
		"ha":                  cl.HA,
		"auto_upgrade":        cl.AutoUpgrade,
		"surge_upgrade":       cl.SurgeUpgrade,
		"registry_integrated": cl.RegistryEnabled,
		"maintenance_window":  mw,
		"node_pool_count":     len(cl.NodePools),
		"tags":                append([]string{}, cl.Tags...),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", DOKSClusterType, cl.RegionSlug, cl.Name),
		Type:       DOKSClusterType,
		Name:       cl.Name,
		Provider:   providerName,
		Region:     cl.RegionSlug,
		Attributes: attrs,
	}
	c.stamp(&r, cl.RegionSlug)
	return r
}

func (c *Collector) doksNodePoolResource(cl *godo.KubernetesCluster, np *godo.KubernetesNodePool) core.Resource {
	taints := make([]map[string]string, 0, len(np.Taints))
	for _, t := range np.Taints {
		taints = append(taints, map[string]string{
			"key":    t.Key,
			"value":  t.Value,
			"effect": t.Effect,
		})
	}
	attrs := map[string]any{
		"cluster_name":    cl.Name,
		"region":          cl.RegionSlug,
		"size":            np.Size,
		"count":           np.Count,
		"auto_scale":      np.AutoScale,
		"min_nodes":       np.MinNodes,
		"max_nodes":       np.MaxNodes,
		"taints":          taints,
		"tags":            append([]string{}, np.Tags...),
		"node_count_live": len(np.Nodes),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", DOKSNodePoolType, cl.RegionSlug, cl.Name, np.Name),
		Type:       DOKSNodePoolType,
		Name:       np.Name,
		Provider:   providerName,
		Region:     cl.RegionSlug,
		Attributes: attrs,
	}
	c.stamp(&r, cl.RegionSlug)
	return r
}
