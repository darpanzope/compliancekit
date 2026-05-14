package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// RDSInstanceType is the resource type for RDS DB instances.
const RDSInstanceType = "aws.rds.instance"

// rdsClient is the subset of *rds.Client the collector uses.
type rdsClient interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

func (c *Collector) collectRDS(ctx context.Context, regions []string, out []core.Resource) []core.Resource {
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		updated, err := c.collectRDSWithClient(ctx, rds.NewFromConfig(cfg), region, out)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "rds", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectRDSWithClient(ctx context.Context, client rdsClient, region string, out []core.Resource) ([]core.Resource, error) {
	var marker *string
	for {
		page, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("rds describe instances: %w", err)
		}
		for _, db := range page.DBInstances {
			id := awssdk.ToString(db.DBInstanceIdentifier)
			r := core.Resource{
				ID:       fmt.Sprintf("aws.rds.instance.%s.%s", region, id),
				Type:     RDSInstanceType,
				Name:     id,
				Provider: providerName,
				Attributes: map[string]any{
					"db_instance_id":          id,
					"engine":                  awssdk.ToString(db.Engine),
					"db_instance_class":       awssdk.ToString(db.DBInstanceClass),
					"storage_encrypted":       awssdk.ToBool(db.StorageEncrypted),
					"publicly_accessible":     awssdk.ToBool(db.PubliclyAccessible),
					"backup_retention_period": int(awssdk.ToInt32(db.BackupRetentionPeriod)),
					"deletion_protection":     awssdk.ToBool(db.DeletionProtection),
					"multi_az":                awssdk.ToBool(db.MultiAZ),
					"db_instance_status":      awssdk.ToString(db.DBInstanceStatus),
				},
			}
			cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
				AccountID: c.accountID,
				Region:    region,
			})
			out = append(out, r)
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	return out, nil
}
