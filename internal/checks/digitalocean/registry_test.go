package digitalocean

import (
	"context"
	"testing"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkRegistry(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.registry." + name,
		Type:       docol.RegistryType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestRegistryGarbageCollection(t *testing.T) {
	now := time.Now().UTC()
	g := newAccountGraph(
		mkRegistry("recent", map[string]any{"last_gc_at": now.Add(-7 * 24 * time.Hour)}),
		mkRegistry("stale", map[string]any{"last_gc_at": now.Add(-60 * 24 * time.Hour)}),
		mkRegistry("never", map[string]any{}),
	)
	findings, _ := RegistryGarbageCollection(context.Background(), g)
	for _, f := range findings {
		var want core.Status
		switch f.Resource.Name {
		case "recent":
			want = core.StatusPass
		case "stale", "never":
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v: %s", f.Resource.Name, f.Status, f.Message)
		}
	}
}

func TestRegistryHasRepositories(t *testing.T) {
	g := newAccountGraph(
		mkRegistry("populated", map[string]any{"repository_count": 5}),
		mkRegistry("empty", map[string]any{"repository_count": 0}),
	)
	findings, _ := RegistryHasRepositories(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "empty" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestRegistryNotStarterTier(t *testing.T) {
	g := newAccountGraph(
		mkRegistry("basic", map[string]any{"subscription_tier": "basic"}),
		mkRegistry("starter", map[string]any{"subscription_tier": "starter"}),
	)
	findings, _ := RegistryNotStarterTier(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "starter" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
