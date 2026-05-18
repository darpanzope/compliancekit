package digitalocean

import (
	"context"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkVPC(name string, isDefault bool, members int) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "digitalocean.vpc." + name,
		Type:     docol.VPCType,
		Name:     name,
		Provider: "digitalocean",
		Attributes: map[string]any{
			"is_default":   isDefault,
			"member_count": members,
		},
	}
}

func mkLB(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.load_balancer." + name,
		Type:       docol.LoadBalancerType,
		Name:       name,
		Provider:   "digitalocean",
		Attributes: attrs,
	}
}

func TestVPCDefaultNotInUse(t *testing.T) {
	cases := []struct {
		name      string
		isDefault bool
		members   int
		want      compliancekit.Status
	}{
		{"named-vpc", false, 3, compliancekit.StatusPass},
		{"empty-default", true, 0, compliancekit.StatusPass},
		{"populated-default", true, 5, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkVPC(c.name, c.isDefault, c.members))
			findings, _ := VPCDefaultNotInUse(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestVPCOrphan(t *testing.T) {
	g := newAccountGraph(
		mkVPC("populated", false, 2),
		mkVPC("orphan", false, 0),
		mkVPC("default-skip", true, 0),
	)
	findings, _ := VPCOrphan(context.Background(), g)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (default VPC should be skipped)", len(findings))
	}
}

func TestLBRedirectHTTPToHTTPS(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  compliancekit.Status
	}{
		{
			"no-http",
			map[string]any{
				"forwarding_rules": []map[string]any{
					{"entry_protocol": "https", "entry_port": 443},
				},
			},
			compliancekit.StatusPass,
		},
		{
			"http-with-redirect",
			map[string]any{
				"forwarding_rules": []map[string]any{
					{"entry_protocol": "http", "entry_port": 80},
					{"entry_protocol": "https", "entry_port": 443},
				},
				"redirect_http_to_https": true,
			},
			compliancekit.StatusPass,
		},
		{
			"http-no-redirect",
			map[string]any{
				"forwarding_rules": []map[string]any{
					{"entry_protocol": "http", "entry_port": 80},
				},
				"redirect_http_to_https": false,
			},
			compliancekit.StatusFail,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkLB(c.name, c.attrs))
			findings, _ := LBRedirectHTTPToHTTPS(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestLBHasHTTPS(t *testing.T) {
	g := newAccountGraph(
		mkLB("https-lb", map[string]any{"forwarding_rules": []map[string]any{
			{"entry_protocol": "https", "entry_port": 443},
		}}),
		mkLB("http-only", map[string]any{"forwarding_rules": []map[string]any{
			{"entry_protocol": "http", "entry_port": 80},
		}}),
	)
	findings, _ := LBHasHTTPS(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "http-only" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestLBHealthCheckProtocol(t *testing.T) {
	g := newAccountGraph(
		mkLB("https-http-hc", map[string]any{
			"forwarding_rules": []map[string]any{{"entry_protocol": "https", "entry_port": 443}},
			"health_check":     map[string]any{"protocol": "http", "port": 80},
		}),
		mkLB("https-https-hc", map[string]any{
			"forwarding_rules": []map[string]any{{"entry_protocol": "https", "entry_port": 443}},
			"health_check":     map[string]any{"protocol": "https", "port": 443},
		}),
		mkLB("http-only-with-http-hc", map[string]any{
			"forwarding_rules": []map[string]any{{"entry_protocol": "http", "entry_port": 80}},
			"health_check":     map[string]any{"protocol": "http", "port": 80},
		}),
	)
	findings, _ := LBHealthCheckProtocol(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "https-http-hc" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v: %s", f.Resource.Name, f.Status, f.Message)
		}
	}
}

func TestLBInVPC(t *testing.T) {
	g := newAccountGraph(
		mkLB("vpc-lb", map[string]any{"vpc_uuid": "vpc-1"}),
		mkLB("legacy-lb", map[string]any{"vpc_uuid": ""}),
	)
	findings, _ := LBInVPC(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "legacy-lb" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestLBOrphan(t *testing.T) {
	g := newAccountGraph(
		mkLB("has-droplets", map[string]any{"droplet_ids": []int{1, 2}, "droplet_tag": ""}),
		mkLB("has-tag", map[string]any{"droplet_ids": []int{}, "droplet_tag": "web"}),
		mkLB("orphan", map[string]any{"droplet_ids": []int{}, "droplet_tag": ""}),
	)
	findings, _ := LBOrphan(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "orphan" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
