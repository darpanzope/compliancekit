package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	logging "cloud.google.com/go/logging/apiv2"
	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	// LogSinkType holds project-level log export sinks (per CIS
	// GCP Foundations 2.2 every project needs at least one sink
	// exporting log entries off the platform).
	LogSinkType = "gcp.logging.sink"

	// LogBucketType holds project-level log buckets, including
	// _Default and _Required. Retention checks read this.
	LogBucketType = "gcp.logging.bucket"
)

// collectLogging enumerates Cloud Logging sinks + buckets per
// project. Per-project errors emit a placeholder and continue.
func (c *Collector) collectLogging(ctx context.Context, out []core.Resource) []core.Resource {
	for _, projectID := range c.projects {
		updated, err := c.collectLoggingForProject(ctx, projectID, out)
		if err != nil {
			out = append(out, c.projectErrorResource(projectID, "logging", err))
			continue
		}
		out = updated
	}
	return out
}

func (c *Collector) collectLoggingForProject(ctx context.Context, projectID string, out []core.Resource) ([]core.Resource, error) {
	client, err := logging.NewConfigClient(ctx, c.clientOption())
	if err != nil {
		return out, fmt.Errorf("new logging config client: %w", err)
	}
	defer func() { _ = client.Close() }()

	sinkIt := client.ListSinks(ctx, &loggingpb.ListSinksRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
	})
	for {
		s, err := sinkIt.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list sinks: %w", err)
		}
		out = append(out, c.logSinkResource(projectID, s))
	}

	// "-" wildcard returns buckets across all locations.
	bucketIt := client.ListBuckets(ctx, &loggingpb.ListBucketsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
	})
	for {
		b, err := bucketIt.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("list log buckets: %w", err)
		}
		out = append(out, c.logBucketResource(projectID, b))
	}
	return out, nil
}

func (c *Collector) logSinkResource(projectID string, s *loggingpb.LogSink) core.Resource {
	dest := s.Destination
	destType := sinkDestinationType(dest)
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.logging.sink.%s.%s", projectID, s.Name),
		Type:     LogSinkType,
		Name:     s.Name,
		Provider: providerName,
		Attributes: map[string]any{
			"sink_name":        s.Name,
			"destination":      dest,
			"destination_type": destType,
			"filter":           s.Filter,
			"disabled":         s.Disabled,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{AccountID: projectID})
	return r
}

func (c *Collector) logBucketResource(projectID string, b *loggingpb.LogBucket) core.Resource {
	// b.Name is "projects/<p>/locations/<loc>/buckets/<name>".
	short := lastPathSegment(b.Name)
	location := bucketLocation(b.Name)
	r := core.Resource{
		ID:       fmt.Sprintf("gcp.logging.bucket.%s.%s.%s", projectID, location, short),
		Type:     LogBucketType,
		Name:     short,
		Provider: providerName,
		Attributes: map[string]any{
			"bucket_name":    short,
			"full_name":      b.Name,
			"location":       location,
			"retention_days": int(b.RetentionDays),
			"locked":         b.Locked,
		},
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: projectID,
		Region:    location,
	})
	return r
}

// sinkDestinationType buckets sink destinations into the four
// supported families so checks read a single attribute instead of
// reparsing the destination URI.
func sinkDestinationType(dest string) string {
	switch {
	case strings.HasPrefix(dest, "storage.googleapis.com/"):
		return "gcs"
	case strings.HasPrefix(dest, "bigquery.googleapis.com/"):
		return "bigquery"
	case strings.HasPrefix(dest, "pubsub.googleapis.com/"):
		return "pubsub"
	case strings.HasPrefix(dest, "logging.googleapis.com/"):
		return "logging-bucket"
	default:
		return "unknown"
	}
}

// bucketLocation extracts the location segment from a fully
// qualified log bucket name. Returns "global" when the path
// doesn't match the expected projects/<p>/locations/<loc>/buckets/...
// shape.
func bucketLocation(fullName string) string {
	parts := strings.Split(fullName, "/")
	for i, p := range parts {
		if p == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "global"
}
