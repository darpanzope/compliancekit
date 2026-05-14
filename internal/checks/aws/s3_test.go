package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

func newBucketGraph(attrs map[string]any) *core.ResourceGraph {
	g := core.NewResourceGraph()
	g.Add(core.Resource{
		ID:         "aws.s3.bucket.test",
		Type:       awscol.S3BucketType,
		Name:       "test",
		Provider:   "aws",
		Region:     "us-east-1",
		Attributes: attrs,
	})
	return g
}

func TestS3PublicAccessBlock(t *testing.T) {
	allOn := map[string]any{
		"block_public_acls":       true,
		"ignore_public_acls":      true,
		"block_public_policy":     true,
		"restrict_public_buckets": true,
		"configured":              true,
	}
	someOff := map[string]any{
		"block_public_acls":       true,
		"ignore_public_acls":      true,
		"block_public_policy":     false,
		"restrict_public_buckets": false,
		"configured":              true,
	}

	cases := []struct {
		name string
		pab  map[string]any
		want core.Status
	}{
		{"all on", allOn, core.StatusPass},
		{"some off", someOff, core.StatusFail},
		{"not configured", map[string]any{"configured": false}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newBucketGraph(map[string]any{"public_access_block": c.pab})
			findings, _ := S3PublicAccessBlock(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestS3DefaultEncryption(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  core.Status
	}{
		{"AES256", map[string]any{"default_encryption_configured": true, "default_encryption_algorithm": "AES256"}, core.StatusPass},
		{"aws:kms", map[string]any{"default_encryption_configured": true, "default_encryption_algorithm": "aws:kms"}, core.StatusPass},
		{"not configured", map[string]any{"default_encryption_configured": false}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newBucketGraph(c.attrs)
			findings, _ := S3DefaultEncryption(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestS3Versioning(t *testing.T) {
	cases := []struct {
		status string
		want   core.Status
	}{
		{"Enabled", core.StatusPass},
		{"Suspended", core.StatusFail},
		{"", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.status, func(t *testing.T) {
			g := newBucketGraph(map[string]any{"versioning_status": c.status})
			findings, _ := S3Versioning(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestS3Logging(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  core.Status
	}{
		{"enabled to other bucket", map[string]any{"logging_enabled": true, "logging_target_bucket": "logs"}, core.StatusPass},
		{"disabled", map[string]any{"logging_enabled": false}, core.StatusFail},
		{"loop", map[string]any{"logging_enabled": true, "logging_target_bucket": "test"}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newBucketGraph(c.attrs)
			findings, _ := S3Logging(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestS3NoPublicACLs(t *testing.T) {
	cases := []struct {
		public bool
		want   core.Status
	}{
		{false, core.StatusPass},
		{true, core.StatusFail},
	}
	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			g := newBucketGraph(map[string]any{"public_acls": c.public})
			findings, _ := S3NoPublicACLs(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}
