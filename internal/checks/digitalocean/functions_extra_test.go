package digitalocean

import (
	"context"
	"strings"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkFnNS(name, region string, attrs map[string]any) compliancekit.Resource {
	r := compliancekit.Resource{
		ID:         "digitalocean.functions_namespace." + name,
		Type:       docol.FunctionsNamespaceType,
		Name:       name,
		Provider:   "digitalocean",
		Region:     region,
		Attributes: attrs,
	}
	return r
}

func TestFnNamespaceRegion(t *testing.T) {
	cases := []struct {
		name, region string
		want         compliancekit.Status
	}{
		{"with region", "nyc1", compliancekit.StatusPass},
		{"no region", "", compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFnNS("ns", c.region, nil))
			findings, _ := FnNamespaceRegion(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestFnAllTriggersEnabledRatio(t *testing.T) {
	cases := []struct {
		name string
		t, e int
		want compliancekit.Status
	}{
		{"no triggers → skip", 0, 0, ""},
		{"all enabled", 4, 4, compliancekit.StatusPass},
		{"partial disabled", 4, 3, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkFnNS("ns", "nyc1", map[string]any{
				"trigger_count":         c.t,
				"enabled_trigger_count": c.e,
			}))
			findings, _ := FnAllTriggersEnabledRatio(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings")
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestFnAccessKeyMinimum(t *testing.T) {
	g := newAccountGraph(
		mkFnNS("with", "nyc1", map[string]any{"access_key_count": 1}),
		mkFnNS("without", "nyc1", map[string]any{"access_key_count": 0}),
	)
	findings, _ := FnAccessKeyMinimum(context.Background(), g)
	byName := map[string]compliancekit.Status{}
	for _, f := range findings {
		byName[f.Resource.Name] = f.Status
	}
	if byName["with"] != compliancekit.StatusPass || byName["without"] != compliancekit.StatusFail {
		t.Errorf("statuses=%+v", byName)
	}
}

func TestFnManualVerifyChecks(t *testing.T) {
	g := newAccountGraph(mkFnNS("ns", "nyc1", nil))
	cases := []struct {
		name string
		fn   func(context.Context, *compliancekit.ResourceGraph) ([]compliancekit.Finding, error)
		hint string
	}{
		{"key rotation", FnAccessKeyRotation, "list-keys"},
		{"runtime", FnRuntimeNotEOL, "runtime"},
		{"env vars", FnEnvVarsEncrypted, "env-var"},
		{"secret scan", FnSourceSecretScan, "gitleaks"},
		{"log export", FnLogExport, "doctl serverless"},
		{"cold start", FnColdStartMitigation, "scheduled"},
		{"env tag", FnNamespaceEnvironmentTag, "digitalocean.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), g)
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("status=%v want StatusError", findings[0].Status)
			}
			if !strings.Contains(strings.ToLower(findings[0].Message), c.hint) {
				t.Errorf("message %q missing %q", findings[0].Message, c.hint)
			}
		})
	}
}
