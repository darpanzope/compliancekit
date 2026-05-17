package digitalocean

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 5 — App Platform depth tests.

func TestAppServicesHealthcheck(t *testing.T) {
	cases := []struct {
		name  string
		total int
		cov   int
		want  core.Status
	}{
		{"no services", 0, 0, ""},
		{"all covered", 3, 3, core.StatusPass},
		{"partial", 3, 2, core.StatusFail},
		{"none covered", 3, 0, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkApp("a", map[string]any{
				"service_count":             c.total,
				"services_with_healthcheck": c.cov,
			}))
			findings, _ := AppServicesHealthcheck(context.Background(), g)
			if c.want == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestAppTierProdGrade(t *testing.T) {
	cases := []struct {
		name string
		tier string
		want core.Status
	}{
		{"basic-xxs fails", "basic-xxs", core.StatusFail},
		{"basic-m fails", "basic-m", core.StatusFail},
		{"professional-xs passes", "professional-xs", core.StatusPass},
		{"professional-s passes", "professional-s", core.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkApp("a", map[string]any{"tier_slug": c.tier}))
			findings, _ := AppTierProdGrade(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestAppDatabaseProduction(t *testing.T) {
	cases := []struct {
		name    string
		total   int
		managed int
		want    core.Status
	}{
		{"no dbs → skip", 0, 0, ""},
		{"all managed", 2, 2, core.StatusPass},
		{"mixed", 2, 1, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkApp("a", map[string]any{
				"database_count":   c.total,
				"managed_db_count": c.managed,
			}))
			findings, _ := AppDatabaseProduction(context.Background(), g)
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

func TestAppDomainTLS13(t *testing.T) {
	cases := []struct {
		name    string
		domains []map[string]any
		expectN int
		want    core.Status
	}{
		{"no domains", nil, 0, ""},
		{"all 1.3", []map[string]any{{"domain": "a", "minimum_tls_version": "1.3"}}, 1, core.StatusPass},
		{"mixed", []map[string]any{{"domain": "a", "minimum_tls_version": "1.2"}, {"domain": "b", "minimum_tls_version": "1.3"}}, 1, core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := map[string]any{}
			if c.domains != nil {
				attrs["domains"] = c.domains
			}
			g := newAccountGraph(mkApp("a", attrs))
			findings, _ := AppDomainTLS13(context.Background(), g)
			if c.expectN == 0 {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestAppManualVerifyChecks(t *testing.T) {
	cases := []struct {
		name      string
		attrs     map[string]any
		fn        func(context.Context, *core.ResourceGraph) ([]core.Finding, error)
		expectN   int
		urlMatch  string
		wantClass core.Status
	}{
		{"deploy-on-push fires when set", map[string]any{"services_deploy_on_push": 1}, AppDeployOnPushProtection, 1, "github.com", core.StatusError},
		{"deploy-on-push skips when 0", map[string]any{"services_deploy_on_push": 0}, AppDeployOnPushProtection, 0, "", ""},
		{"build secret scan always fires", nil, AppBuildSecretScan, 1, "gitleaks", core.StatusError},
		{"cert rotation skips no domains", map[string]any{"has_custom_domains": false}, AppDomainCertRotation, 0, "", ""},
		{"cert rotation fires with domains", map[string]any{"has_custom_domains": true}, AppDomainCertRotation, 1, "digitalocean.com", core.StatusError},
		{"cdn attachment always fires", nil, AppCDNAttachment, 1, "spaces", core.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkApp("a", c.attrs))
			findings, _ := c.fn(context.Background(), g)
			if len(findings) != c.expectN {
				t.Fatalf("findings=%d want %d", len(findings), c.expectN)
			}
			if c.expectN == 0 {
				return
			}
			if findings[0].Status != c.wantClass {
				t.Errorf("status=%v want %v", findings[0].Status, c.wantClass)
			}
			if !strings.Contains(findings[0].Message, c.urlMatch) {
				t.Errorf("message %q missing %q", findings[0].Message, c.urlMatch)
			}
		})
	}
}
