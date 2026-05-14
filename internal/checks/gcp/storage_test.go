package gcp

import (
	"context"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkBucket(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID: "gcp.storage.bucket." + name, Type: gcpcol.GCSBucketType, Name: name, Provider: "gcp",
		Attributes: attrs,
	}
}

func TestGCSUniformAccess(t *testing.T) {
	cases := []struct {
		name string
		on   bool
		want core.Status
	}{
		{"enabled", true, core.StatusPass},
		{"disabled", false, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkBucket("b", map[string]any{"uniform_bucket_level_access": c.on}))
			findings, _ := GCSUniformAccess(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestGCSPAP(t *testing.T) {
	cases := []struct {
		pap  string
		want core.Status
	}{
		{"enforced", core.StatusPass},
		{"inherited", core.StatusFail},
		{"", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.pap, func(t *testing.T) {
			g := newGraphWith(mkBucket("b", map[string]any{"public_access_prevention": c.pap}))
			findings, _ := GCSPAP(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestGCSVersioning(t *testing.T) {
	g := newGraphWith(
		mkBucket("on", map[string]any{"versioning_enabled": true}),
		mkBucket("off", map[string]any{"versioning_enabled": false}),
	)
	findings, _ := GCSVersioning(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "off" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestGCSLogging(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  core.Status
	}{
		{"disabled", map[string]any{"logging_enabled": false}, core.StatusFail},
		{"enabled-other-target", map[string]any{"logging_enabled": true, "logging_target_bucket": "logs"}, core.StatusPass},
		{"loop", map[string]any{"logging_enabled": true, "logging_target_bucket": "b"}, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkBucket("b", c.attrs))
			findings, _ := GCSLogging(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}
