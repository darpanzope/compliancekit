package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkBucket(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.spaces_bucket.nyc3." + name,
		Type:       docol.SpacesBucketType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func mkSpacesKey(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.spaces_key." + name,
		Type:       docol.SpacesKeyType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestSpacesNotPublic(t *testing.T) {
	g := newAccountGraph(
		mkBucket("private", map[string]any{"acl_has_public_grant": false}),
		mkBucket("public", map[string]any{"acl_has_public_grant": true}),
	)
	findings, _ := SpacesNotPublic(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "public" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesVersioning(t *testing.T) {
	g := newAccountGraph(
		mkBucket("on", map[string]any{"versioning_enabled": true}),
		mkBucket("off", map[string]any{"versioning_enabled": false}),
	)
	findings, _ := SpacesVersioning(context.Background(), g)
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

func TestSpacesEncryption(t *testing.T) {
	g := newAccountGraph(
		mkBucket("enc", map[string]any{"encryption_configured": true}),
		mkBucket("noenc", map[string]any{"encryption_configured": false}),
	)
	findings, _ := SpacesEncryption(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "noenc" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesLifecycle(t *testing.T) {
	g := newAccountGraph(
		mkBucket("lc", map[string]any{"lifecycle_configured": true}),
		mkBucket("nolc", map[string]any{"lifecycle_configured": false}),
	)
	findings, _ := SpacesLifecycle(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "nolc" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesCORSWildcard(t *testing.T) {
	g := newAccountGraph(
		mkBucket("safe", map[string]any{"cors_wildcard_origin": false}),
		mkBucket("wildcard", map[string]any{"cors_wildcard_origin": true}),
	)
	findings, _ := SpacesCORSWildcard(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "wildcard" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesLogging(t *testing.T) {
	g := newAccountGraph(
		mkBucket("logged", map[string]any{"logging_enabled": true}),
		mkBucket("unlogged", map[string]any{"logging_enabled": false}),
	)
	findings, _ := SpacesLogging(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "unlogged" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesKeyNotFullAccess(t *testing.T) {
	g := newAccountGraph(
		mkSpacesKey("scoped", map[string]any{"is_full_access": false, "grant_count": 2}),
		mkSpacesKey("full", map[string]any{"is_full_access": true, "grant_count": 0}),
	)
	findings, _ := SpacesKeyNotFullAccess(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "full" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestSpacesKeyAge(t *testing.T) {
	now := time.Now().UTC()
	g := newAccountGraph(
		mkSpacesKey("fresh", map[string]any{"created_at": now.Add(-100 * 24 * time.Hour).Format(time.RFC3339)}),
		mkSpacesKey("old", map[string]any{"created_at": now.Add(-400 * 24 * time.Hour).Format(time.RFC3339)}),
		mkSpacesKey("bad-date", map[string]any{"created_at": "junk"}),
	)
	findings, _ := SpacesKeyAge(context.Background(), g)
	for _, f := range findings {
		var want core.Status
		switch f.Resource.Name {
		case "fresh":
			want = core.StatusPass
		case "old":
			want = core.StatusFail
		case "bad-date":
			want = core.StatusSkip
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
