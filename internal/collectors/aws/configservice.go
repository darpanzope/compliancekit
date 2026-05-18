package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// ConfigRegionType is the resource type for AWS Config service
// state per region. One resource per region in scope; checks
// anchor on this type and ask "is Config enabled here?"
const ConfigRegionType = "aws.config.region"

// configClient is the subset of *configservice.Client used here.
type configClient interface {
	DescribeConfigurationRecorders(ctx context.Context, in *configservice.DescribeConfigurationRecordersInput, opts ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(ctx context.Context, in *configservice.DescribeConfigurationRecorderStatusInput, opts ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
	DescribeDeliveryChannels(ctx context.Context, in *configservice.DescribeDeliveryChannelsInput, opts ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error)
}

// collectConfig emits one aws.config.region resource per region in
// scope, describing whether AWS Config has an active recorder and
// delivery channel there. The presence of the resource alone is
// the signal -- the check reads its attributes to determine pass
// or fail.
func (c *Collector) collectConfig(ctx context.Context, regions []string, out []compliancekit.Resource) []compliancekit.Resource {
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		r, err := c.collectConfigForRegion(ctx, configservice.NewFromConfig(cfg), region)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "configservice", err))
			continue
		}
		out = append(out, r)
	}
	return out
}

func (c *Collector) collectConfigForRegion(ctx context.Context, client configClient, region string) (compliancekit.Resource, error) {
	r := compliancekit.Resource{
		ID:       fmt.Sprintf("aws.config.region.%s", region),
		Type:     ConfigRegionType,
		Name:     region,
		Provider: providerName,
		Attributes: map[string]any{
			"recorder_present": false,
			"recorder_on":      false,
			"delivery_channel": false,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    region,
	})

	recs, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return r, fmt.Errorf("describe configuration recorders: %w", err)
	}
	if len(recs.ConfigurationRecorders) > 0 {
		r.Attributes["recorder_present"] = true
		r.Attributes["recorder_name"] = awssdk.ToString(recs.ConfigurationRecorders[0].Name)
	}

	statuses, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return r, fmt.Errorf("describe configuration recorder status: %w", err)
	}
	for _, s := range statuses.ConfigurationRecordersStatus {
		if s.Recording {
			r.Attributes["recorder_on"] = true
			break
		}
	}

	channels, err := client.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{})
	if err != nil {
		return r, fmt.Errorf("describe delivery channels: %w", err)
	}
	r.Attributes["delivery_channel"] = len(channels.DeliveryChannels) > 0
	return r, nil
}
