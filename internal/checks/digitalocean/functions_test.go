package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkNS(name string, attrs map[string]any) core.Resource {
	return core.Resource{
		ID:         "digitalocean.functions_namespace." + name,
		Type:       docol.FunctionsNamespaceType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestFunctionsHasAccessKey(t *testing.T) {
	g := newAccountGraph(
		mkNS("with", map[string]any{"access_key_count": 2}),
		mkNS("without", map[string]any{"access_key_count": 0}),
	)
	findings, _ := FunctionsHasAccessKey(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "without" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestFunctionsOrphan(t *testing.T) {
	g := newAccountGraph(
		mkNS("active", map[string]any{"trigger_count": 3}),
		mkNS("empty", map[string]any{"trigger_count": 0}),
	)
	findings, _ := FunctionsOrphan(context.Background(), g)
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

func TestFunctionsAllTriggersEnabled(t *testing.T) {
	g := newAccountGraph(
		mkNS("all-on", map[string]any{"trigger_count": 3, "enabled_trigger_count": 3}),
		mkNS("partial", map[string]any{"trigger_count": 3, "enabled_trigger_count": 2}),
		mkNS("empty", map[string]any{"trigger_count": 0, "enabled_trigger_count": 0}),
	)
	findings, _ := FunctionsAllTriggersEnabled(context.Background(), g)
	for _, f := range findings {
		want := core.StatusPass
		if f.Resource.Name == "partial" {
			want = core.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
