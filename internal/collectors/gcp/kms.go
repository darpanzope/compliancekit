package gcp

import (
	"context"
	"errors"
	"fmt"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// KMSCryptoKeyType holds GCP KMS CryptoKey resources. Rotation
// and IAM separation checks consume this type. One resource per
// key per location per project.
const KMSCryptoKeyType = "gcp.kms.crypto_key"

// collectKMS enumerates KMS CryptoKeys per project. Walks
// locations -> keyrings -> keys and attaches each key's IAM
// policy. Per-project errors emit a placeholder and continue.
func (c *Collector) collectKMS(ctx context.Context, out []core.Resource) []core.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectKMSForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "kms", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectKMSForProject(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := kms.NewKeyManagementClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new kms client: %w", err)
	}
	defer func() { _ = client.Close() }()

	locIt := client.ListLocations(ctx, &locationpb.ListLocationsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	})
	for {
		loc, err := locIt.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list locations: %w", err)
		}

		ringIt := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{
			Parent: loc.Name, // projects/<p>/locations/<loc>
		})
		for {
			ring, err := ringIt.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return out, fmt.Errorf("list key rings: %w", err)
			}

			keyIt := client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{
				Parent: ring.Name,
			})
			for {
				key, err := keyIt.Next()
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					return out, fmt.Errorf("list crypto keys: %w", err)
				}
				out = append(out, c.kmsKeyResource(ctx, client, projectID, loc.LocationId, ring, key))
			}
		}
	}
	return out, nil
}

func (c *Collector) kmsKeyResource(ctx context.Context, client *kms.KeyManagementClient, projectID, locationID string, ring *kmspb.KeyRing, key *kmspb.CryptoKey) core.Resource {
	keyShort := lastPathSegment(key.Name)
	ringShort := lastPathSegment(ring.Name)

	rotationSeconds := int64(0)
	if rp := key.GetRotationPeriod(); rp != nil {
		rotationSeconds = rp.Seconds
	}
	rotationDays := rotationSeconds / 86400

	r := core.Resource{
		ID:       fmt.Sprintf("gcp.kms.crypto_key.%s.%s.%s.%s", projectID, locationID, ringShort, keyShort),
		Type:     KMSCryptoKeyType,
		Name:     keyShort,
		Provider: providerName,
		Attributes: map[string]any{
			"key_name":                keyShort,
			"full_name":               key.Name,
			"key_ring":                ringShort,
			"location":                locationID,
			"purpose":                 key.Purpose.String(),
			"is_encrypt_decrypt":      key.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT,
			"has_rotation_schedule":   rotationSeconds > 0,
			"rotation_period_days":    int(rotationDays),
			"rotation_period_seconds": rotationSeconds,
			"import_only":             key.ImportOnly,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    locationID,
	})

	// Per-key IAM policy. Failure is captured as an attribute
	// rather than failing the whole key — the rotation check is
	// independent of IAM and shouldn't lose data because the
	// caller can't read the IAM policy.
	pol, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: key.Name,
	})
	if err != nil {
		r.Attributes["collect_error_iam"] = err.Error()
		r.Attributes["iam_bindings"] = []map[string]any{}
		return r
	}
	bindings := []map[string]any{}
	for _, b := range pol.Bindings {
		bindings = append(bindings, map[string]any{
			"role":    b.Role,
			"members": append([]string(nil), b.Members...),
		})
	}
	r.Attributes["iam_bindings"] = bindings
	return r
}
