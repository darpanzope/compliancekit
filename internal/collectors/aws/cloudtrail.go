package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CloudTrailType is the resource type for CloudTrail trails.
const CloudTrailType = "aws.cloudtrail.trail"

// cloudtrailClient is the subset of *cloudtrail.Client used here.
type cloudtrailClient interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// collectCloudTrail enumerates trails per region. A multi-region
// trail is described in every region it is "home" in; we de-dup
// by trail ARN so the global trail does not produce N findings.
func (c *Collector) collectCloudTrail(ctx context.Context, regions []string, out []compliancekit.Resource) []compliancekit.Resource {
	seen := map[string]bool{}
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		updated, err := c.collectCloudTrailWithClient(ctx, cloudtrail.NewFromConfig(cfg), region, seen, out)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "cloudtrail", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectCloudTrailWithClient(ctx context.Context, client cloudtrailClient, region string, seen map[string]bool, out []compliancekit.Resource) ([]compliancekit.Resource, error) {
	resp, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe trails: %w", err)
	}
	for _, t := range resp.TrailList {
		arn := awssdk.ToString(t.TrailARN)
		if seen[arn] {
			continue
		}
		seen[arn] = true

		// Trail status (logging or not) is per-region; query in the
		// trail's home region. For a trail with a home region
		// different from the listing region, we issue a fresh client
		// against the home region.
		homeRegion := awssdk.ToString(t.HomeRegion)
		statusClient := client
		if homeRegion != "" && homeRegion != region {
			cfg := c.cfg
			cfg.Region = homeRegion
			statusClient = cloudtrail.NewFromConfig(cfg)
		}
		isLogging := false
		if status, err := statusClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil {
			isLogging = awssdk.ToBool(status.IsLogging)
		}

		r := compliancekit.Resource{
			ID:       fmt.Sprintf("aws.cloudtrail.trail.%s", arn),
			Type:     CloudTrailType,
			Name:     awssdk.ToString(t.Name),
			Provider: providerName,
			Attributes: map[string]any{
				"trail_arn":                   arn,
				"is_multi_region":             awssdk.ToBool(t.IsMultiRegionTrail),
				"is_organization_trail":       awssdk.ToBool(t.IsOrganizationTrail),
				"log_file_validation_enabled": awssdk.ToBool(t.LogFileValidationEnabled),
				"is_logging":                  isLogging,
				"home_region":                 homeRegion,
				"s3_bucket_name":              awssdk.ToString(t.S3BucketName),
			},
		}
		cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
			AccountID: c.accountID,
			Region:    homeRegion,
		})
		out = append(out, r)
	}
	return out, nil
}
