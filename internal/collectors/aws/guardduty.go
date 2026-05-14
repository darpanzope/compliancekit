package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// GuardDutyRegionType is the resource type emitted per region for
// GuardDuty state. One resource per region in scope.
const GuardDutyRegionType = "aws.guardduty.region"

// guarddutyClient is the subset of *guardduty.Client used here.
type guarddutyClient interface {
	ListDetectors(ctx context.Context, in *guardduty.ListDetectorsInput, opts ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, in *guardduty.GetDetectorInput, opts ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// collectGuardDuty emits one aws.guardduty.region resource per
// region in scope, indicating whether GuardDuty has a detector
// and whether it is enabled.
func (c *Collector) collectGuardDuty(ctx context.Context, regions []string, out []core.Resource) []core.Resource {
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		r, err := c.collectGuardDutyForRegion(ctx, guardduty.NewFromConfig(cfg), region)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "guardduty", err))
			continue
		}
		out = append(out, r)
	}
	return out
}

func (c *Collector) collectGuardDutyForRegion(ctx context.Context, client guarddutyClient, region string) (core.Resource, error) {
	r := core.Resource{
		ID:       fmt.Sprintf("aws.guardduty.region.%s", region),
		Type:     GuardDutyRegionType,
		Name:     region,
		Provider: providerName,
		Attributes: map[string]any{
			"detector_present": false,
			"detector_enabled": false,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    region,
	})

	dets, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return r, fmt.Errorf("list detectors: %w", err)
	}
	if len(dets.DetectorIds) == 0 {
		return r, nil
	}
	id := dets.DetectorIds[0]
	r.Attributes["detector_present"] = true
	r.Attributes["detector_id"] = id

	det, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: awssdk.String(id)})
	if err != nil {
		// Intentional: we record the error on the resource and let
		// the scan continue rather than abort. ListDetectors gave us
		// the detector_id already, so the check has enough to surface
		// a partial finding.
		r.Attributes["collect_error_detector"] = err.Error()
		return r, nil //nolint:nilerr // captured as resource attribute
	}
	r.Attributes["detector_enabled"] = det.Status == gdtypes.DetectorStatusEnabled
	return r, nil
}
