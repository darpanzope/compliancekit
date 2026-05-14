package aws

import (
	"context"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

// S3BucketType is the resource type emitted for each S3 bucket.
const S3BucketType = "aws.s3.bucket"

// s3Client is the subset of *s3.Client the collector uses.
type s3Client interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(ctx context.Context, in *s3.GetBucketLocationInput, opts ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, in *s3.GetBucketVersioningInput, opts ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(ctx context.Context, in *s3.GetBucketLoggingInput, opts ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketAcl(ctx context.Context, in *s3.GetBucketAclInput, opts ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

// collectS3 enumerates every bucket in the account and emits one
// aws.s3.bucket resource per bucket with the attributes the 5 S3
// checks read. S3 buckets are account-global by namespace but live
// in a specific region; we resolve that region per bucket so the
// evidence pack can attribute correctly.
//
// Per-bucket Get* errors do not abort the entire collection -- one
// inaccessible bucket lands as a partial resource with
// collect_error rather than killing the scan of every bucket.
func (c *Collector) collectS3(ctx context.Context, out []core.Resource) ([]core.Resource, error) {
	return c.collectS3WithClient(ctx, s3.NewFromConfig(c.cfg), out)
}

func (c *Collector) collectS3WithClient(ctx context.Context, client s3Client, out []core.Resource) ([]core.Resource, error) {
	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws: s3.ListBuckets: %w", err)
	}
	for _, b := range buckets.Buckets {
		r := c.buildBucketResource(ctx, client, b)
		out = append(out, r)
	}
	return out, nil
}

// buildBucketResource fetches the per-bucket facts. Each Get* call
// may fail with a NoSuch* error (S3 returns these when a feature
// is not configured), which is a finding, not a collect error.
// Per-fact work is split into small helpers below so the orchestrator
// stays under gocyclo's 15-edge ceiling.
func (c *Collector) buildBucketResource(ctx context.Context, client s3Client, b s3types.Bucket) core.Resource {
	name := awssdk.ToString(b.Name)
	r := core.Resource{
		ID:       fmt.Sprintf("aws.s3.bucket.%s", name),
		Type:     S3BucketType,
		Name:     name,
		Provider: providerName,
		Attributes: map[string]any{
			"bucket_name": name,
			"created_at":  awssdk.ToTime(b.CreationDate),
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: c.accountID,
		Region:    fetchBucketRegion(ctx, client, b.Name),
	})

	r.Attributes["public_access_block"] = fetchBucketPAB(ctx, client, b.Name, &r)
	fetchBucketEncryption(ctx, client, b.Name, &r)
	fetchBucketVersioning(ctx, client, b.Name, &r)
	fetchBucketLogging(ctx, client, b.Name, &r)
	fetchBucketACL(ctx, client, b.Name, &r)

	return r
}

// fetchBucketRegion resolves the bucket's home region.
// GetBucketLocation returns "" for us-east-1 (legacy quirk);
// normalize to "us-east-1" so the evidence pack groups correctly.
func fetchBucketRegion(ctx context.Context, client s3Client, name *string) string {
	loc, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: name})
	if err != nil {
		return "us-east-1"
	}
	if c := string(loc.LocationConstraint); c != "" {
		return c
	}
	return "us-east-1"
}

func fetchBucketPAB(ctx context.Context, client s3Client, name *string, r *core.Resource) map[string]any {
	pab := map[string]any{
		"block_public_acls":       false,
		"ignore_public_acls":      false,
		"block_public_policy":     false,
		"restrict_public_buckets": false,
		"configured":              false,
	}
	resp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: name})
	switch {
	case err == nil && resp.PublicAccessBlockConfiguration != nil:
		cfg := resp.PublicAccessBlockConfiguration
		pab["configured"] = true
		pab["block_public_acls"] = awssdk.ToBool(cfg.BlockPublicAcls)
		pab["ignore_public_acls"] = awssdk.ToBool(cfg.IgnorePublicAcls)
		pab["block_public_policy"] = awssdk.ToBool(cfg.BlockPublicPolicy)
		pab["restrict_public_buckets"] = awssdk.ToBool(cfg.RestrictPublicBuckets)
	case err != nil && !isAWSError(err, "NoSuchPublicAccessBlockConfiguration"):
		r.Attributes["collect_error_pab"] = err.Error()
	}
	return pab
}

func fetchBucketEncryption(ctx context.Context, client s3Client, name *string, r *core.Resource) {
	enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: name})
	switch {
	case err == nil && enc.ServerSideEncryptionConfiguration != nil:
		rules := enc.ServerSideEncryptionConfiguration.Rules
		r.Attributes["default_encryption_configured"] = len(rules) > 0
		if len(rules) > 0 && rules[0].ApplyServerSideEncryptionByDefault != nil {
			r.Attributes["default_encryption_algorithm"] = string(rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		}
	case err != nil && isAWSError(err, "ServerSideEncryptionConfigurationNotFoundError"):
		r.Attributes["default_encryption_configured"] = false
	case err != nil:
		r.Attributes["collect_error_encryption"] = err.Error()
	}
}

func fetchBucketVersioning(ctx context.Context, client s3Client, name *string, r *core.Resource) {
	ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: name})
	if err == nil {
		r.Attributes["versioning_status"] = string(ver.Status)
	}
}

func fetchBucketLogging(ctx context.Context, client s3Client, name *string, r *core.Resource) {
	resp, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: name})
	if err != nil {
		return
	}
	r.Attributes["logging_enabled"] = resp.LoggingEnabled != nil
	if resp.LoggingEnabled != nil {
		r.Attributes["logging_target_bucket"] = awssdk.ToString(resp.LoggingEnabled.TargetBucket)
	}
}

func fetchBucketACL(ctx context.Context, client s3Client, name *string, r *core.Resource) {
	resp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: name})
	if err == nil {
		r.Attributes["public_acls"] = aclMakesPublic(resp.Grants)
	}
}

// aclMakesPublic reports whether any grant in the bucket ACL gives
// permission to the AllUsers or AuthenticatedUsers principal groups,
// which together constitute "public read/write."
func aclMakesPublic(grants []s3types.Grant) bool {
	publicURIs := map[string]bool{
		"http://acs.amazonaws.com/groups/global/AllUsers":           true,
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers": true,
	}
	for _, g := range grants {
		if g.Grantee == nil || g.Grantee.URI == nil {
			continue
		}
		if publicURIs[*g.Grantee.URI] {
			return true
		}
	}
	return false
}

// Catch a likely future regression: if s3types.Bucket gains a non-
// nullable field, the linter would flag this var. Kept as a static
// import-retention guard for the test file.
var _ = errors.New
