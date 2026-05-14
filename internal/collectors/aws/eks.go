package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// EKSClusterType is the resource type for EKS clusters. v0.11 phase 8
// emits one per cluster across the scoped regions, plus k8s.eks_nodegroup
// per managed node group.
const (
	EKSClusterType   = "aws.eks.cluster"
	EKSNodegroupType = "aws.eks.nodegroup"
)

type eksClient interface {
	ListClusters(ctx context.Context, in *eks.ListClustersInput, opts ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, opts ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListNodegroups(ctx context.Context, in *eks.ListNodegroupsInput, opts ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(ctx context.Context, in *eks.DescribeNodegroupInput, opts ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
}

// collectEKS enumerates EKS clusters and node groups per region.
func (c *Collector) collectEKS(ctx context.Context, regions []string, out []core.Resource) []core.Resource {
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		updated, err := c.collectEKSInRegion(ctx, eks.NewFromConfig(cfg), region, out)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "eks", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectEKSInRegion(ctx context.Context, client eksClient, region string, out []core.Resource) ([]core.Resource, error) {
	listResp, err := client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("list clusters: %w", err)
	}
	for _, name := range listResp.Clusters {
		descResp, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, fmt.Errorf("describe %q: %w", name, err)
		}
		if descResp.Cluster == nil {
			continue
		}
		out = append(out, c.eksClusterResource(region, descResp.Cluster))

		// Node groups.
		ngList, err := client.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: awssdk.String(name)})
		if err != nil {
			continue
		}
		for _, ngName := range ngList.Nodegroups {
			ngDesc, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   awssdk.String(name),
				NodegroupName: awssdk.String(ngName),
			})
			if err != nil || ngDesc.Nodegroup == nil {
				continue
			}
			out = append(out, c.eksNodegroupResource(region, name, ngDesc.Nodegroup))
		}
	}
	return out, nil
}

func (c *Collector) eksClusterResource(region string, cl *ekstypes.Cluster) core.Resource {
	name := awssdk.ToString(cl.Name)
	publicAccess := false
	publicCIDRs := []string{}
	privateAccess := false
	if cl.ResourcesVpcConfig != nil {
		publicAccess = cl.ResourcesVpcConfig.EndpointPublicAccess
		privateAccess = cl.ResourcesVpcConfig.EndpointPrivateAccess
		publicCIDRs = append(publicCIDRs, cl.ResourcesVpcConfig.PublicAccessCidrs...)
	}
	hasSecretsKMS := false
	for _, ec := range cl.EncryptionConfig {
		if ec.Provider != nil && awssdk.ToString(ec.Provider.KeyArn) != "" {
			hasSecretsKMS = true
		}
	}
	logTypes := map[string]bool{}
	if cl.Logging != nil {
		for _, l := range cl.Logging.ClusterLogging {
			if l.Enabled != nil && *l.Enabled {
				for _, t := range l.Types {
					logTypes[string(t)] = true
				}
			}
		}
	}
	hasOIDC := false
	if cl.Identity != nil && cl.Identity.Oidc != nil && awssdk.ToString(cl.Identity.Oidc.Issuer) != "" {
		hasOIDC = true
	}
	authMode := ""
	if cl.AccessConfig != nil {
		authMode = string(cl.AccessConfig.AuthenticationMode)
	}

	attrs := map[string]any{
		"version":             awssdk.ToString(cl.Version),
		"status":              string(cl.Status),
		"endpoint":            awssdk.ToString(cl.Endpoint),
		"endpoint_public":     publicAccess,
		"endpoint_private":    privateAccess,
		"public_access_cidrs": publicCIDRs,
		"has_secrets_kms":     hasSecretsKMS,
		"log_types_enabled":   keysOfBoolMap(logTypes),
		"has_oidc":            hasOIDC,
		"authentication_mode": authMode,
		"role_arn":            awssdk.ToString(cl.RoleArn),
		"platform_version":    awssdk.ToString(cl.PlatformVersion),
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", EKSClusterType, region, name),
		Type:       EKSClusterType,
		Name:       name,
		Provider:   providerName,
		Region:     region,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.accountID, Region: region})
	return r
}

func (c *Collector) eksNodegroupResource(region, clusterName string, ng *ekstypes.Nodegroup) core.Resource {
	name := awssdk.ToString(ng.NodegroupName)
	amiType := string(ng.AmiType)
	imdsHopLimit := int32(-1)
	if ng.LaunchTemplate != nil {
		imdsHopLimit = 0 // sentinel meaning "launch template — unknown without further fetch"
	}
	publicIPs := false
	if ng.NodeRole != nil && len(ng.Subnets) > 0 {
		// Treat as a hint: managed NGs honor the subnet's "map public IP on launch"
		// flag. We cannot resolve subnet metadata cheaply here; emit best-effort.
		publicIPs = false
	}
	remoteAccess := false
	if ng.RemoteAccess != nil && awssdk.ToString(ng.RemoteAccess.Ec2SshKey) != "" {
		remoteAccess = true
	}
	attrs := map[string]any{
		"cluster_name":        clusterName,
		"ami_type":            amiType,
		"capacity_type":       string(ng.CapacityType),
		"instance_types":      append([]string{}, ng.InstanceTypes...),
		"version":             awssdk.ToString(ng.Version),
		"release_version":     awssdk.ToString(ng.ReleaseVersion),
		"status":              string(ng.Status),
		"has_launch_template": ng.LaunchTemplate != nil,
		"imds_hop_limit":      imdsHopLimit,
		"public_ips":          publicIPs,
		"remote_access_ssh":   remoteAccess,
	}
	r := core.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", EKSNodegroupType, region, clusterName, name),
		Type:       EKSNodegroupType,
		Name:       name,
		Provider:   providerName,
		Region:     region,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: c.accountID, Region: region})
	return r
}

func keysOfBoolMap(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	return out
}
