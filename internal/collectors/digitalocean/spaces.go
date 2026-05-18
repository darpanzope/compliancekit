package digitalocean

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// SpacesBucketType is the resource type for DO Spaces buckets
// (the S3-compatible object stores). Discovered + inspected via
// aws-sdk-go-v2/s3 with a DO endpoint, not via godo, because the
// Spaces bucket API is not part of the DO v2 control API.
const SpacesBucketType = "digitalocean.spaces_bucket"

// defaultSpacesRegion is the endpoint we use for the initial
// ListBuckets call. ListBuckets returns every bucket the account
// owns across every region, so any single region works. nyc3 is
// the longest-lived DO region.
const defaultSpacesRegion = "nyc3"

// spacesEndpoint builds the per-region DO Spaces endpoint URL.
// Spaces uses <region>.digitaloceanspaces.com with HTTPS.
func spacesEndpoint(region string) string {
	return fmt.Sprintf("https://%s.digitaloceanspaces.com", region)
}

// collectSpaces enumerates Spaces buckets and queries the
// security-relevant config on each. The collector is a no-op
// (zero resources, nil error) when SPACES_KEY or SPACES_SECRET
// env vars are unset -- Spaces auth is independent from the
// main DO API token, and not every operator who uses DO uses
// Spaces.
func (c *Collector) collectSpaces(ctx context.Context) ([]compliancekit.Resource, error) {
	key := os.Getenv("SPACES_KEY")
	secret := os.Getenv("SPACES_SECRET")
	if key == "" || secret == "" {
		return nil, nil
	}

	creds := credentials.NewStaticCredentialsProvider(key, secret, "")
	cfg := aws.Config{
		Region:       defaultSpacesRegion,
		Credentials:  creds,
		BaseEndpoint: aws.String(spacesEndpoint(defaultSpacesRegion)),
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = false
	})

	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("spaces list buckets: %w", err)
	}

	out := []compliancekit.Resource{}
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		region, regErr := bucketRegion(ctx, client, name)
		if regErr != nil {
			region = defaultSpacesRegion
		}

		regionalClient := s3.NewFromConfig(aws.Config{
			Region:       region,
			Credentials:  creds,
			BaseEndpoint: aws.String(spacesEndpoint(region)),
		}, func(o *s3.Options) {
			o.UsePathStyle = false
		})

		out = append(out, c.spacesBucketResource(ctx, regionalClient, name, region, aws.ToTime(b.CreationDate)))
	}
	return out, nil
}

// bucketRegion resolves the per-bucket region via
// GetBucketLocation. DO returns the region slug in
// LocationConstraint.
func bucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", err
	}
	loc := string(out.LocationConstraint)
	if loc == "" {
		return defaultSpacesRegion, nil
	}
	return loc, nil
}

// spacesBucketResource collects security-relevant config for a
// single Spaces bucket. Per-bucket API calls (ACL, versioning,
// encryption, etc.) are independent; any failure is captured as
// a collect_error_<field> attribute rather than aborting the
// whole bucket. Check code reads pass/fail off the booleans.
func (c *Collector) spacesBucketResource(ctx context.Context, client *s3.Client, bucket, region string, created any) compliancekit.Resource {
	attrs := map[string]any{
		"bucket_name": bucket,
		"region":      region,
		"created_at":  created,
	}

	// ACL
	if acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)}); err == nil {
		attrs["acl_has_public_grant"] = aclHasPublicGrant(acl)
	} else {
		attrs["collect_error_acl"] = err.Error()
	}

	// Versioning
	if v, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)}); err == nil {
		attrs["versioning_enabled"] = v.Status == s3types.BucketVersioningStatusEnabled
	} else {
		attrs["collect_error_versioning"] = err.Error()
	}

	// Lifecycle — v0.19 phase 2 surfaces rule-level detail so checks
	// can distinguish "lifecycle configured but covers nothing useful"
	// from "fully-configured lifecycle". The previous boolean alone is
	// kept for back-compat with the existing CheckSpacesLifecycle.
	collectSpacesLifecycle(ctx, client, bucket, attrs)

	// Encryption
	_, encErr := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)})
	attrs["encryption_configured"] = encErr == nil
	if encErr != nil && !isNoSuchConfigurationErr(encErr) {
		attrs["collect_error_encryption"] = encErr.Error()
	}

	// CORS
	cors, corsErr := client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: aws.String(bucket)})
	if corsErr == nil {
		attrs["cors_wildcard_origin"] = corsHasWildcardOrigin(cors)
	} else {
		attrs["cors_wildcard_origin"] = false
		if !isNoSuchConfigurationErr(corsErr) {
			attrs["collect_error_cors"] = corsErr.Error()
		}
	}

	// Logging — v0.19 phase 2 also captures the target bucket and
	// prefix so checks can flag "logs writing to the source bucket"
	// (audit/operations footgun) and "logs going somewhere we don't
	// control" (the prefix needs review).
	collectSpacesLogging(ctx, client, bucket, attrs)

	// Bucket policy — v0.19 phase 2 introduces a policy_configured
	// boolean. We don't capture the policy body here: the body is
	// JSON and downstream policies (or the Rego ruleset) can parse
	// it themselves once we widen the surface. For phase 2 we only
	// need "policy exists" vs "policy missing" to flag prod buckets
	// without an explicit deny posture.
	collectSpacesPolicy(ctx, client, bucket, attrs)

	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s", SpacesBucketType, region, bucket),
		Type:       SpacesBucketType,
		Name:       bucket,
		Provider:   providerName,
		Attributes: attrs,
	}
	c.stamp(&r, region)
	return r
}

// collectSpacesLifecycle fetches GetBucketLifecycleConfiguration and
// writes lifecycle_configured + per-rule summary attrs. Extracted
// from spacesBucketResource to keep cyclomatic complexity under the
// project ceiling.
func collectSpacesLifecycle(ctx context.Context, client *s3.Client, bucket string, attrs map[string]any) {
	lcResp, lcErr := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(bucket)})
	attrs["lifecycle_configured"] = lcErr == nil
	if lcErr != nil && !isNoSuchConfigurationErr(lcErr) {
		attrs["collect_error_lifecycle"] = lcErr.Error()
	}
	if lcErr != nil || lcResp == nil {
		return
	}
	attrs["lifecycle_rule_count"] = len(lcResp.Rules)
	hasExp, hasMPU := false, false
	for _, rule := range lcResp.Rules {
		if rule.Expiration != nil {
			hasExp = true
		}
		if rule.AbortIncompleteMultipartUpload != nil {
			hasMPU = true
		}
	}
	attrs["lifecycle_has_expiration"] = hasExp
	attrs["lifecycle_has_mpu_abort"] = hasMPU
}

// collectSpacesLogging fetches GetBucketLogging and writes
// logging_enabled + target attrs. Extracted for complexity.
func collectSpacesLogging(ctx context.Context, client *s3.Client, bucket string, attrs map[string]any) {
	logging, logErr := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: aws.String(bucket)})
	if logErr != nil {
		attrs["collect_error_logging"] = logErr.Error()
		return
	}
	attrs["logging_enabled"] = logging.LoggingEnabled != nil
	if logging.LoggingEnabled != nil {
		attrs["logging_target_bucket"] = aws.ToString(logging.LoggingEnabled.TargetBucket)
		attrs["logging_target_prefix"] = aws.ToString(logging.LoggingEnabled.TargetPrefix)
	}
}

// collectSpacesPolicy fetches GetBucketPolicy and writes
// policy_configured. Extracted for complexity.
func collectSpacesPolicy(ctx context.Context, client *s3.Client, bucket string, attrs map[string]any) {
	_, polErr := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	attrs["policy_configured"] = polErr == nil
	if polErr != nil && !isNoSuchConfigurationErr(polErr) {
		attrs["collect_error_policy"] = polErr.Error()
	}
}

// aclHasPublicGrant returns true if any Grantee on the ACL
// is the well-known AllUsers or AuthenticatedUsers group URI.
func aclHasPublicGrant(acl *s3.GetBucketAclOutput) bool {
	for _, g := range acl.Grants {
		if g.Grantee == nil || g.Grantee.URI == nil {
			continue
		}
		uri := *g.Grantee.URI
		if uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
			uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
			return true
		}
	}
	return false
}

// corsHasWildcardOrigin returns true if any CORS rule allows
// origin "*". CORS-anywhere is the standard misconfiguration
// that turns a private bucket into a browser-accessible one.
func corsHasWildcardOrigin(cors *s3.GetBucketCorsOutput) bool {
	for _, rule := range cors.CORSRules {
		for _, origin := range rule.AllowedOrigins {
			if origin == "*" {
				return true
			}
		}
	}
	return false
}

// isNoSuchConfigurationErr returns true when the S3 error is the
// expected "no <foo> configuration found" shape -- not a real
// error. Spaces returns slightly different codes for each
// configuration type so a substring match is reliable.
func isNoSuchConfigurationErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"NoSuchLifecycleConfiguration",
		"NoSuchCORSConfiguration",
		"ServerSideEncryptionConfigurationNotFoundError",
		"NoSuchBucketPolicy",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
