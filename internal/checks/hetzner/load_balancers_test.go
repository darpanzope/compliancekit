package hetzner

import (
	"context"
	"testing"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkLB(name string, services []map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "hetzner.load_balancer." + name,
		Type:       hetznercol.LoadBalancerType,
		Name:       name,
		Provider:   "hetzner",
		Attributes: map[string]any{"services": services},
	}
}

func TestLBHTTPSListener(t *testing.T) {
	g := newGraphWith(
		mkLB("https", []map[string]any{{"protocol": "https"}}),
		mkLB("http-only", []map[string]any{{"protocol": "http"}}),
		mkLB("tcp", []map[string]any{{"protocol": "tcp"}}),
	)
	findings, _ := LBHTTPSListener(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusFail
		if f.Resource.Name == "https" {
			want = compliancekit.StatusPass
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestLBHTTPRedirect(t *testing.T) {
	g := newGraphWith(
		mkLB("no-http", []map[string]any{{"protocol": "https"}}),
		mkLB("http-redirected", []map[string]any{{"protocol": "http", "redirect_http": true}}),
		mkLB("http-cleartext", []map[string]any{{"protocol": "http", "redirect_http": false}}),
	)
	findings, _ := LBHTTPRedirect(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "http-cleartext" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
