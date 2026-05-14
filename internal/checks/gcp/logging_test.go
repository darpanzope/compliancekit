package gcp

import (
	"context"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkProject(projectID string) core.Resource {
	return core.Resource{
		ID:         "gcp.project." + projectID,
		Type:       gcpcol.ProjectType,
		Name:       projectID,
		Provider:   "gcp",
		Attributes: map[string]any{"project_id": projectID, "account_id": projectID},
	}
}

func mkSink(name, projectID, destType string, disabled bool) core.Resource {
	return core.Resource{
		ID:       "gcp.logging.sink." + projectID + "." + name,
		Type:     gcpcol.LogSinkType,
		Name:     name,
		Provider: "gcp",
		Attributes: map[string]any{
			"sink_name":        name,
			"destination":      destType + "://x",
			"destination_type": destType,
			"disabled":         disabled,
			"account_id":       projectID,
		},
	}
}

func mkLogBucket(short, projectID string, retention int) core.Resource {
	return core.Resource{
		ID:       "gcp.logging.bucket." + projectID + ".global." + short,
		Type:     gcpcol.LogBucketType,
		Name:     short,
		Provider: "gcp",
		Attributes: map[string]any{
			"bucket_name":    short,
			"retention_days": retention,
			"account_id":     projectID,
		},
	}
}

func TestLoggingSinkExists(t *testing.T) {
	cases := []struct {
		name      string
		resources []core.Resource
		want      core.Status
	}{
		{
			"long-term-gcs",
			[]core.Resource{
				mkProject("p1"),
				mkSink("export", "p1", "gcs", false),
			},
			core.StatusPass,
		},
		{
			"long-term-bigquery",
			[]core.Resource{
				mkProject("p1"),
				mkSink("export", "p1", "bigquery", false),
			},
			core.StatusPass,
		},
		{
			"only-logging-bucket",
			[]core.Resource{
				mkProject("p1"),
				mkSink("back-to-bucket", "p1", "logging-bucket", false),
			},
			core.StatusFail,
		},
		{
			"disabled-sink",
			[]core.Resource{
				mkProject("p1"),
				mkSink("export", "p1", "gcs", true),
			},
			core.StatusFail,
		},
		{
			"no-sinks",
			[]core.Resource{mkProject("p1")},
			core.StatusFail,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(c.resources...)
			findings, _ := LoggingSinkExists(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestLogBucketRetention(t *testing.T) {
	cases := []struct {
		short     string
		retention int
		want      core.Status
		skipped   bool
	}{
		{"_Default", 30, core.StatusFail, false},
		{"_Default", 365, core.StatusPass, false},
		{"custom", 400, core.StatusPass, false},
		{"_Required", 0, core.StatusPass, true}, // _Required is skipped entirely; want unused
	}
	for _, c := range cases {
		t.Run(c.short, func(t *testing.T) {
			g := newGraphWith(mkLogBucket(c.short, "p1", c.retention))
			findings, _ := LogBucketRetention(context.Background(), g)
			if c.skipped {
				if len(findings) != 0 {
					t.Fatalf("_Required should be skipped, got %d findings", len(findings))
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}
