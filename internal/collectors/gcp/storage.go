package gcp

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const GCSBucketType = "gcp.storage.bucket"

// collectStorage enumerates Cloud Storage buckets per project.
func (c *Collector) collectStorage(ctx context.Context, out []core.Resource) []core.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectStorageForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "storage", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectStorageForProject(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := storage.NewClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new storage client: %w", err)
	}
	defer func() { _ = client.Close() }()

	it := client.Buckets(ctx, projectID)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list buckets: %w", err)
		}
		out = append(out, c.bucketResource(projectID, attrs))
	}
	return out, nil
}

func (c *Collector) bucketResource(projectID string, attrs *storage.BucketAttrs) core.Resource {
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.storage.bucket.%s.%s", projectID, attrs.Name),
		Type:     GCSBucketType,
		Name:     attrs.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"bucket_name":                 attrs.Name,
			"location":                    attrs.Location,
			"location_type":               attrs.LocationType,
			"storage_class":               attrs.StorageClass,
			"uniform_bucket_level_access": attrs.UniformBucketLevelAccess.Enabled,
			"public_access_prevention":    attrs.PublicAccessPrevention.String(),
			"versioning_enabled":          attrs.VersioningEnabled,
			"logging_enabled":             attrs.Logging != nil && attrs.Logging.LogBucket != "",
			"logging_target_bucket":       loggingTarget(attrs),
			"default_kms_key":             attrs.Encryption != nil && attrs.Encryption.DefaultKMSKeyName != "",
			"default_kms_key_name":        defaultKMSKey(attrs),
			"requester_pays":              attrs.RequesterPays,
			"retention_policy_locked":     attrs.RetentionPolicy != nil && attrs.RetentionPolicy.IsLocked,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    attrs.Location,
	})
	return r
}

func loggingTarget(a *storage.BucketAttrs) string {
	if a.Logging == nil {
		return ""
	}
	return a.Logging.LogBucket
}

func defaultKMSKey(a *storage.BucketAttrs) string {
	if a.Encryption == nil {
		return ""
	}
	return a.Encryption.DefaultKMSKeyName
}
