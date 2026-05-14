package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// KMSKeyType is the resource type for KMS keys.
const KMSKeyType = "aws.kms.key"

// kmsClient is the subset of *kms.Client used here.
type kmsClient interface {
	ListKeys(ctx context.Context, in *kms.ListKeysInput, opts ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, opts ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// collectKMS enumerates KMS keys per region.
func (c *Collector) collectKMS(ctx context.Context, regions []string, out []core.Resource) []core.Resource {
	for _, region := range regions {
		cfg := c.cfg
		cfg.Region = region
		updated, err := c.collectKMSWithClient(ctx, kms.NewFromConfig(cfg), region, out)
		if err != nil {
			out = append(out, c.regionErrorResource(region, "kms", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectKMSWithClient(ctx context.Context, client kmsClient, region string, out []core.Resource) ([]core.Resource, error) {
	var marker *string
	for {
		page, err := client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		for _, entry := range page.Keys {
			r := c.buildKMSResource(ctx, client, entry, region)
			out = append(out, r)
		}
		if page.NextMarker == nil || *page.NextMarker == "" {
			break
		}
		marker = page.NextMarker
	}
	return out, nil
}

func (c *Collector) buildKMSResource(ctx context.Context, client kmsClient, entry kmstypes.KeyListEntry, region string) core.Resource {
	keyID := awssdk.ToString(entry.KeyId)
	r := core.Resource{
		ID:       fmt.Sprintf("aws.kms.key.%s.%s", region, keyID),
		Type:     KMSKeyType,
		Name:     keyID,
		Provider: providerName,
		Attributes: map[string]any{
			"key_id":  keyID,
			"key_arn": awssdk.ToString(entry.KeyArn),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    region,
	})

	desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyId})
	if err != nil || desc.KeyMetadata == nil {
		r.Attributes["collect_error_describe"] = fmt.Sprintf("%v", err)
		return r
	}
	md := desc.KeyMetadata
	r.Attributes["key_manager"] = string(md.KeyManager) // CUSTOMER or AWS
	r.Attributes["key_state"] = string(md.KeyState)     // Enabled, Disabled, PendingDeletion, ...
	r.Attributes["key_spec"] = string(md.KeySpec)       // SYMMETRIC_DEFAULT, RSA_2048, ...
	r.Attributes["enabled"] = md.Enabled
	r.Attributes["description"] = awssdk.ToString(md.Description)

	// Rotation only applies to customer-managed symmetric CMKs and
	// only when the key is not pending deletion. For other shapes
	// rotation_enabled is nil ("not applicable") so the check
	// surfaces a skip rather than a misleading pass/fail.
	if md.KeyManager == kmstypes.KeyManagerTypeCustomer &&
		md.KeySpec == kmstypes.KeySpecSymmetricDefault &&
		md.KeyState != kmstypes.KeyStatePendingDeletion {
		rot, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: entry.KeyId})
		if err != nil {
			r.Attributes["collect_error_rotation"] = err.Error()
		} else {
			r.Attributes["rotation_enabled"] = rot.KeyRotationEnabled
		}
	} else {
		r.Attributes["rotation_enabled"] = nil
	}
	return r
}
