package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkApp(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.app." + name,
		Type:       docol.AppType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestAppNoPlainEnvs(t *testing.T) {
	g := newAccountGraph(
		mkApp("clean", map[string]any{"plain_env_count": 3}),
		mkApp("messy", map[string]any{"plain_env_count": 10}),
	)
	findings, _ := AppNoPlainEnvs(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "messy" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestAppCustomDomain(t *testing.T) {
	g := newAccountGraph(
		mkApp("with", map[string]any{"has_custom_domains": true}),
		mkApp("without", map[string]any{"has_custom_domains": false}),
	)
	findings, _ := AppCustomDomain(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "without" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestAppDomainTLSVersion(t *testing.T) {
	g := newAccountGraph(
		mkApp("strong", map[string]any{"domains": []map[string]any{
			{"domain": "a.example.com", "minimum_tls_version": "1.2"},
		}}),
		mkApp("weak", map[string]any{"domains": []map[string]any{
			{"domain": "b.example.com", "minimum_tls_version": "1.0"},
		}}),
	)
	findings, _ := AppDomainTLSVersion(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "weak" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestAppHasAlerts(t *testing.T) {
	g := newAccountGraph(
		mkApp("alerts", map[string]any{"has_alerts": true}),
		mkApp("no-alerts", map[string]any{"has_alerts": false}),
	)
	findings, _ := AppHasAlerts(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "no-alerts" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestAppInVPC(t *testing.T) {
	g := newAccountGraph(
		mkApp("vpc", map[string]any{"in_vpc": true}),
		mkApp("no-vpc", map[string]any{"in_vpc": false}),
	)
	findings, _ := AppInVPC(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "no-vpc" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
