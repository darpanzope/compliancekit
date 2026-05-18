package k8s

import (
	"context"
	"strings"
	"testing"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 4 — tests for the 10 DOKS-depth checks.

func mkDOKSCluster(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.doks.cluster.nyc3." + name,
		Type:       docol.DOKSClusterType,
		Name:       name,
		Provider:   "digitalocean",
		Region:     "nyc3",
		Attributes: attrs,
	}
}

func mkDOKSPool(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "digitalocean.doks.nodepool.nyc3.c." + name,
		Type:       docol.DOKSNodePoolType,
		Name:       name,
		Provider:   "digitalocean",
		Region:     "nyc3",
		Attributes: attrs,
	}
}

func graph(rs ...compliancekit.Resource) *compliancekit.ResourceGraph {
	g := compliancekit.NewResourceGraph()
	for _, r := range rs {
		g.Add(r)
	}
	return g
}

func TestDOKSVersionSupported(t *testing.T) {
	cases := []struct {
		name string
		ver  string
		want compliancekit.Status
	}{
		{"supported 1.30", "1.30.5-do.0", compliancekit.StatusPass},
		{"deprecated 1.26", "1.26.10-do.4", compliancekit.StatusFail},
		{"deprecated 1.22", "1.22.0-do.0", compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph(mkDOKSCluster("k", map[string]any{"version": c.ver}))
			findings, _ := DOKSVersionSupported(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (ver=%s)", findings[0].Status, c.want, c.ver)
			}
		})
	}
}

func TestDOKSNodepoolTaints(t *testing.T) {
	cases := []struct {
		name    string
		pool    string
		taints  []map[string]string
		expectN int
		want    compliancekit.Status
	}{
		{"default-pool skipped", "default-pool", nil, 0, ""},
		{"named no taints", "gpu", nil, 1, compliancekit.StatusFail},
		{"named with taints", "gpu", []map[string]string{{"key": "dedicated", "value": "gpu", "effect": "NoSchedule"}}, 1, compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph(mkDOKSPool(c.pool, map[string]any{"taints": c.taints}))
			findings, _ := DOKSNodepoolTaints(context.Background(), g)
			if len(findings) != c.expectN {
				t.Fatalf("findings=%d want %d", len(findings), c.expectN)
			}
			if c.want != "" && findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDOKSNodepoolEnvironmentTag(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want compliancekit.Status
	}{
		{"no tags", nil, compliancekit.StatusFail},
		{"env: tag", []string{"env:production"}, compliancekit.StatusPass},
		{"environment: tag", []string{"environment:staging"}, compliancekit.StatusPass},
		{"unrelated tags", []string{"team:platform"}, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph(mkDOKSPool("p", map[string]any{"tags": c.tags}))
			findings, _ := DOKSNodepoolEnvironmentTag(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDOKSNodepoolSizeSupported(t *testing.T) {
	cases := []struct {
		name string
		size string
		want compliancekit.Status
	}{
		{"supported size", "s-2vcpu-4gb", compliancekit.StatusPass},
		{"retired 1vcpu-1gb", "s-1vcpu-1gb", compliancekit.StatusFail},
		{"retired 1vcpu-2gb", "s-1vcpu-2gb", compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph(mkDOKSPool("p", map[string]any{"size": c.size}))
			findings, _ := DOKSNodepoolSizeSupported(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestDOKSMaintenanceQuietHours(t *testing.T) {
	cases := []struct {
		name string
		mw   string
		want compliancekit.Status
	}{
		{"empty", "", compliancekit.StatusFail},
		{"04:00 quiet", "sunday 04:00", compliancekit.StatusPass},
		{"14:00 loud", "tuesday 14:00", compliancekit.StatusFail},
		{"09:00 loud", "monday 09:00", compliancekit.StatusFail},
		{"22:00 quiet", "sunday 22:00", compliancekit.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph(mkDOKSCluster("c", map[string]any{"maintenance_window": c.mw}))
			findings, _ := DOKSMaintenanceQuietHours(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (mw=%q)", findings[0].Status, c.want, c.mw)
			}
		})
	}
}

func TestDOKSManualVerifyChecks(t *testing.T) {
	g := graph(mkDOKSCluster("c", nil))
	cases := []struct {
		name string
		fn   func(context.Context, *compliancekit.ResourceGraph) ([]compliancekit.Finding, error)
		hint string
	}{
		{"control-plane logging", DOKSControlPlaneLogging, "fluent"},
		{"metrics-server", DOKSMetricsServer, "metrics-server"},
		{"cert-manager", DOKSCertManager, "cert-manager"},
		{"cluster autoscaler", DOKSClusterAutoscaler, "node-pool list"},
		{"PSA", DOKSPodSecurityStandards, "pod-security"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), g)
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("status=%v want StatusError", findings[0].Status)
			}
			if !strings.Contains(findings[0].Message, c.hint) {
				t.Errorf("message missing %q: %q", c.hint, findings[0].Message)
			}
		})
	}
}
