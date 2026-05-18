package gcp

import (
	"context"
	"fmt"

	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// GKE resource types. The cluster carries control-plane posture
// attributes; node pool carries per-pool posture.
const (
	GKEClusterType  = "gcp.gke.cluster"
	GKENodePoolType = "gcp.gke.nodepool"
)

// collectGKE enumerates GKE clusters and node pools for each scanned
// project. The list-clusters call accepts a parent of "-" to query
// all locations; per-project errors emit a placeholder.
func (c *Collector) collectGKE(ctx context.Context, out []compliancekit.Resource) []compliancekit.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectGKEForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "gke", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectGKEForProject(ctx context.Context, projectID string, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	client, err := container.NewClusterManagerClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("client: %w", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	})
	if err != nil {
		return out, fmt.Errorf("list clusters: %w", err)
	}
	for _, cl := range resp.Clusters {
		out = append(out, c.gkeClusterResource(projectID, cl))
		for _, np := range cl.NodePools {
			out = append(out, c.gkeNodePoolResource(projectID, cl, np))
		}
	}
	return out, nil
}

func (c *Collector) gkeClusterResource(projectID string, cl *containerpb.Cluster) compliancekit.Resource {
	flags := extractGKEClusterFlags(cl)
	wlIdentity := flags.wlIdentity
	netPolicy := flags.netPolicy
	binAuthz := flags.binAuthz
	privateNodes := flags.privateNodes
	publicCIDRs := flags.publicCIDRs
	shieldedNodes := flags.shieldedNodes
	releaseChannel := flags.releaseChannel
	dbEncryption := flags.dbEncryption
	legacyABAC := flags.legacyABAC
	loggingEnabled := flags.loggingEnabled
	monitoringEnabled := flags.monitoringEnabled

	attrs := map[string]any{
		"location":                cl.Location,
		"current_master_version":  cl.CurrentMasterVersion,
		"current_node_version":    cl.CurrentNodeVersion, //nolint:staticcheck // still surfaces version drift across node pools
		"workload_identity":       wlIdentity,
		"network_policy":          netPolicy,
		"binary_authorization":    binAuthz,
		"private_nodes":           privateNodes,
		"master_authorized_cidrs": publicCIDRs,
		"shielded_nodes":          shieldedNodes,
		"release_channel":         releaseChannel,
		"database_encryption":     dbEncryption,
		"legacy_abac":             legacyABAC,
		"logging_enabled":         loggingEnabled,
		"monitoring_enabled":      monitoringEnabled,
		"status":                  cl.Status.String(),
		"autopilot":               cl.Autopilot != nil && cl.Autopilot.Enabled,
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", GKEClusterType, projectID, cl.Location, cl.Name),
		Type:       GKEClusterType,
		Name:       cl.Name,
		Provider:   providerName,
		Region:     cl.Location,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID, Region: cl.Location})
	return r
}

type gkeClusterFlags struct {
	wlIdentity        bool
	netPolicy         bool
	binAuthz          string
	privateNodes      bool
	publicCIDRs       []string
	shieldedNodes     bool
	releaseChannel    string
	dbEncryption      string
	legacyABAC        bool
	loggingEnabled    bool
	monitoringEnabled bool
}

// extractGKEClusterFlags isolates the option-flag walk so the
// resource builder stays under gocyclo's ceiling. Split into two
// helpers to keep each under the threshold.
func extractGKEClusterFlags(cl *containerpb.Cluster) gkeClusterFlags {
	f := gkeClusterFlags{publicCIDRs: []string{}}
	extractGKEAuthFlags(cl, &f)
	extractGKEHardeningFlags(cl, &f)
	return f
}

func extractGKEAuthFlags(cl *containerpb.Cluster, f *gkeClusterFlags) {
	if cl.WorkloadIdentityConfig != nil && cl.WorkloadIdentityConfig.WorkloadPool != "" {
		f.wlIdentity = true
	}
	if cl.NetworkPolicy != nil && cl.NetworkPolicy.Enabled {
		f.netPolicy = true
	}
	if cl.BinaryAuthorization != nil {
		f.binAuthz = cl.BinaryAuthorization.EvaluationMode.String()
	}
	if cl.PrivateClusterConfig != nil {
		f.privateNodes = cl.PrivateClusterConfig.EnablePrivateNodes //nolint:staticcheck // still populated on existing clusters
	}
	//nolint:staticcheck // GKE v1 keeps both fields populated; reading the deprecated one is intentional.
	if cl.MasterAuthorizedNetworksConfig != nil && cl.MasterAuthorizedNetworksConfig.Enabled {
		for _, b := range cl.MasterAuthorizedNetworksConfig.CidrBlocks {
			f.publicCIDRs = append(f.publicCIDRs, b.CidrBlock)
		}
	}
	if cl.LegacyAbac != nil {
		f.legacyABAC = cl.LegacyAbac.Enabled
	}
}

func extractGKEHardeningFlags(cl *containerpb.Cluster, f *gkeClusterFlags) {
	if cl.ShieldedNodes != nil {
		f.shieldedNodes = cl.ShieldedNodes.Enabled
	}
	if cl.ReleaseChannel != nil {
		f.releaseChannel = cl.ReleaseChannel.Channel.String()
	}
	if cl.DatabaseEncryption != nil {
		f.dbEncryption = cl.DatabaseEncryption.State.String()
	}
	f.loggingEnabled = cl.LoggingService != "" && cl.LoggingService != "none"
	f.monitoringEnabled = cl.MonitoringService != "" && cl.MonitoringService != "none"
}

func (c *Collector) gkeNodePoolResource(projectID string, cl *containerpb.Cluster, np *containerpb.NodePool) compliancekit.Resource {
	autoUpgrade := false
	autoRepair := false
	if np.Management != nil {
		autoUpgrade = np.Management.AutoUpgrade
		autoRepair = np.Management.AutoRepair
	}
	cosImage := false
	defaultSA := false
	shielded := false
	if np.Config != nil {
		// COS_CONTAINERD or COS — both are containerd-based Google
		// hardened images.
		imageType := np.Config.ImageType
		cosImage = imageType == "COS_CONTAINERD" || imageType == "COS"
		defaultSA = np.Config.ServiceAccount == "" || np.Config.ServiceAccount == "default"
		if np.Config.ShieldedInstanceConfig != nil {
			shielded = np.Config.ShieldedInstanceConfig.EnableSecureBoot &&
				np.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring
		}
	}
	autoscaling := false
	if np.Autoscaling != nil {
		autoscaling = np.Autoscaling.Enabled
	}

	attrs := map[string]any{
		"cluster_name":   cl.Name,
		"location":       cl.Location,
		"version":        np.Version,
		"status":         np.Status.String(),
		"auto_upgrade":   autoUpgrade,
		"auto_repair":    autoRepair,
		"cos_image":      cosImage,
		"default_sa":     defaultSA,
		"shielded_nodes": shielded,
		"autoscaling":    autoscaling,
		"initial_count":  int(np.InitialNodeCount),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s.%s", GKENodePoolType, projectID, cl.Location, cl.Name, np.Name),
		Type:       GKENodePoolType,
		Name:       np.Name,
		Provider:   providerName,
		Region:     cl.Location,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID, Region: cl.Location})
	return r
}
