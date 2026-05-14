package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// Per-region EC2 resource types.
const (
	EC2InstanceType = "aws.ec2.instance"
	EC2SGType       = "aws.ec2.security_group"
	EC2VPCType      = "aws.ec2.vpc"
	EC2VolumeType   = "aws.ec2.volume"
	EC2AMIType      = "aws.ec2.ami"
)

// ec2DataClient is the subset of *ec2.Client the data collector
// uses. Distinct from ec2RegionClient (regions.go) which only does
// DescribeRegions; defining two interfaces keeps each test fixture
// minimal.
type ec2DataClient interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(ctx context.Context, in *ec2.DescribeVpcsInput, opts ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, opts ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeImages(ctx context.Context, in *ec2.DescribeImagesInput, opts ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// collectEC2 fans out across the configured regions and emits
// per-region EC2 resources (instances, security groups, VPCs,
// volumes, AMIs owned by this account).
//
// A failure in one region surfaces as a collect_error placeholder
// resource rather than aborting the entire scan -- a transient API
// hiccup in eu-west-3 should not kill findings from every other
// region. The function therefore never returns an error today; the
// signature keeps the (slice, error) shape for symmetry with
// collectIAM / collectS3 so future per-cloud refactors stay uniform.
func (c *Collector) collectEC2(ctx context.Context, regions []string, out []core.Resource) []core.Resource {
	for _, region := range regions {
		updated, err := c.collectEC2InRegion(ctx, region, out)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "ec2", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectEC2InRegion(ctx context.Context, region string, out []core.Resource) ([]core.Resource, error) {
	// Per-region SDK client. The Region field on Options is what the
	// per-service endpoint resolver reads, so we clone the loaded
	// config (cheap; Config is a struct value) with the region set.
	cfg := c.cfg
	cfg.Region = region
	return c.collectEC2WithClient(ctx, ec2.NewFromConfig(cfg), region, out)
}

func (c *Collector) collectEC2WithClient(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	var err error
	if out, err = c.collectEC2Instances(ctx, client, region, out); err != nil {
		return nil, fmt.Errorf("aws ec2 %s: %w", region, err)
	}
	if out, err = c.collectEC2SecurityGroups(ctx, client, region, out); err != nil {
		return nil, fmt.Errorf("aws ec2 %s: %w", region, err)
	}
	if out, err = c.collectEC2VPCs(ctx, client, region, out); err != nil {
		return nil, fmt.Errorf("aws ec2 %s: %w", region, err)
	}
	if out, err = c.collectEC2Volumes(ctx, client, region, out); err != nil {
		return nil, fmt.Errorf("aws ec2 %s: %w", region, err)
	}
	if out, err = c.collectEC2AMIs(ctx, client, region, out); err != nil {
		return nil, fmt.Errorf("aws ec2 %s: %w", region, err)
	}
	return out, nil
}

func (c *Collector) collectEC2Instances(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	resp, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe instances: %w", err)
	}
	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			r := core.Resource{
				ID:       fmt.Sprintf("aws.ec2.instance.%s", awssdk.ToString(inst.InstanceId)),
				Type:     EC2InstanceType,
				Name:     awssdk.ToString(inst.InstanceId),
				Provider: providerName,
				Attributes: map[string]any{
					"instance_id":     awssdk.ToString(inst.InstanceId),
					"image_id":        awssdk.ToString(inst.ImageId),
					"instance_type":   string(inst.InstanceType),
					"state":           string(inst.State.Name),
					"vpc_id":          awssdk.ToString(inst.VpcId),
					"subnet_id":       awssdk.ToString(inst.SubnetId),
					"imdsv2_required": metadataOptionsRequireV2(inst.MetadataOptions),
				},
			}
			cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
				AccountID: c.accountID,
				Region:    region,
			})
			out = append(out, r)
		}
	}
	return out, nil
}

func metadataOptionsRequireV2(opts *ec2types.InstanceMetadataOptionsResponse) bool {
	if opts == nil {
		return false
	}
	return opts.HttpTokens == ec2types.HttpTokensStateRequired
}

func (c *Collector) collectEC2SecurityGroups(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	resp, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe security groups: %w", err)
	}
	for _, sg := range resp.SecurityGroups {
		r := core.Resource{
			ID:       fmt.Sprintf("aws.ec2.sg.%s", awssdk.ToString(sg.GroupId)),
			Type:     EC2SGType,
			Name:     awssdk.ToString(sg.GroupName),
			Provider: providerName,
			Attributes: map[string]any{
				"group_id":       awssdk.ToString(sg.GroupId),
				"group_name":     awssdk.ToString(sg.GroupName),
				"vpc_id":         awssdk.ToString(sg.VpcId),
				"ingress_rules":  ipPermissionsToMaps(sg.IpPermissions),
				"egress_rules":   ipPermissionsToMaps(sg.IpPermissionsEgress),
				"open_to_any_v4": hasOpenIngress(sg.IpPermissions, "0.0.0.0/0"),
				"open_to_any_v6": hasOpenIngress(sg.IpPermissions, "::/0"),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
			AccountID: c.accountID,
			Region:    region,
		})
		out = append(out, r)
	}
	return out, nil
}

// ipPermissionsToMaps projects an IpPermission slice onto the
// map-of-strings shape the checks read. Keeps ec2types.IpPermission
// out of the checks package.
func ipPermissionsToMaps(perms []ec2types.IpPermission) []map[string]any {
	out := make([]map[string]any, 0, len(perms))
	for _, p := range perms {
		entry := map[string]any{
			"protocol":  awssdk.ToString(p.IpProtocol),
			"from_port": int(awssdk.ToInt32(p.FromPort)),
			"to_port":   int(awssdk.ToInt32(p.ToPort)),
		}
		v4 := make([]string, 0, len(p.IpRanges))
		for _, r := range p.IpRanges {
			v4 = append(v4, awssdk.ToString(r.CidrIp))
		}
		entry["ipv4_cidrs"] = v4
		v6 := make([]string, 0, len(p.Ipv6Ranges))
		for _, r := range p.Ipv6Ranges {
			v6 = append(v6, awssdk.ToString(r.CidrIpv6))
		}
		entry["ipv6_cidrs"] = v6
		out = append(out, entry)
	}
	return out
}

func hasOpenIngress(perms []ec2types.IpPermission, cidr string) bool {
	for _, p := range perms {
		for _, r := range p.IpRanges {
			if awssdk.ToString(r.CidrIp) == cidr {
				return true
			}
		}
		for _, r := range p.Ipv6Ranges {
			if awssdk.ToString(r.CidrIpv6) == cidr {
				return true
			}
		}
	}
	return false
}

func (c *Collector) collectEC2VPCs(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	resp, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe vpcs: %w", err)
	}
	for _, v := range resp.Vpcs {
		r := core.Resource{
			ID:       fmt.Sprintf("aws.ec2.vpc.%s", awssdk.ToString(v.VpcId)),
			Type:     EC2VPCType,
			Name:     awssdk.ToString(v.VpcId),
			Provider: providerName,
			Attributes: map[string]any{
				"vpc_id":     awssdk.ToString(v.VpcId),
				"cidr_block": awssdk.ToString(v.CidrBlock),
				"is_default": awssdk.ToBool(v.IsDefault),
				"state":      string(v.State),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
			AccountID: c.accountID,
			Region:    region,
		})
		out = append(out, r)
	}
	return out, nil
}

func (c *Collector) collectEC2Volumes(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	resp, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe volumes: %w", err)
	}
	for _, v := range resp.Volumes {
		r := core.Resource{
			ID:       fmt.Sprintf("aws.ec2.volume.%s", awssdk.ToString(v.VolumeId)),
			Type:     EC2VolumeType,
			Name:     awssdk.ToString(v.VolumeId),
			Provider: providerName,
			Attributes: map[string]any{
				"volume_id":   awssdk.ToString(v.VolumeId),
				"encrypted":   awssdk.ToBool(v.Encrypted),
				"size_gb":     int(awssdk.ToInt32(v.Size)),
				"volume_type": string(v.VolumeType),
				"state":       string(v.State),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
			AccountID: c.accountID,
			Region:    region,
		})
		out = append(out, r)
	}
	return out, nil
}

func (c *Collector) collectEC2AMIs(ctx context.Context, client ec2DataClient, region string, out []core.Resource) ([]core.Resource, error) {
	// Only AMIs owned by this account; public AMIs from third parties
	// are out of scope.
	resp, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, fmt.Errorf("describe images: %w", err)
	}
	for _, img := range resp.Images {
		r := core.Resource{
			ID:       fmt.Sprintf("aws.ec2.ami.%s", awssdk.ToString(img.ImageId)),
			Type:     EC2AMIType,
			Name:     awssdk.ToString(img.Name),
			Provider: providerName,
			Attributes: map[string]any{
				"image_id": awssdk.ToString(img.ImageId),
				"public":   awssdk.ToBool(img.Public),
				"state":    string(img.State),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
			AccountID: c.accountID,
			Region:    region,
		})
		out = append(out, r)
	}
	return out, nil
}

// regionErrorResource emits a placeholder when a per-region collect
// fails outright. Lets the scan continue with findings from working
// regions while still surfacing the failure in the evidence pack.
func (c *Collector) regionErrorResource(region, service string, err error) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("aws.%s.error.%s", service, region),
		Type:     "aws.collect_error",
		Name:     fmt.Sprintf("%s/%s", service, region),
		Provider: providerName,
		Attributes: map[string]any{
			"service": service,
			"error":   err.Error(),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    region,
	})
	return r
}
