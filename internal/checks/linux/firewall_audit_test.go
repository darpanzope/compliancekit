package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// hostWithAttrs is a generic helper for tests that build host
// Resources with arbitrary attribute sub-maps.
func hostWithAttrs(name string, attrs map[string]any) compliancekit.Resource {
	merged := map[string]any{"reachable": true}
	for k, v := range attrs {
		merged[k] = v
	}
	return compliancekit.Resource{
		ID:         "linux.host." + name,
		Type:       linuxcol.HostType,
		Name:       name,
		Provider:   "linux",
		Attributes: merged,
	}
}

func TestFirewallActive(t *testing.T) {
	g := newGraph(t,
		hostWithAttrs("ufw-only", map[string]any{
			"firewall": map[string]any{"ufw_active": true, "nftables_active": false},
		}),
		hostWithAttrs("nft-only", map[string]any{
			"firewall": map[string]any{"ufw_active": false, "nftables_active": true},
		}),
		hostWithAttrs("both", map[string]any{
			"firewall": map[string]any{"ufw_active": true, "nftables_active": true},
		}),
		hostWithAttrs("neither", map[string]any{
			"firewall": map[string]any{"ufw_active": false, "nftables_active": false},
		}),
		unreachableHost("offline", "i/o timeout"),
	)
	findings, err := FirewallActive(context.Background(), g)
	if err != nil {
		t.Fatalf("FirewallActive: %v", err)
	}

	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	want := map[string]compliancekit.Status{
		"ufw-only": compliancekit.StatusPass,
		"nft-only": compliancekit.StatusPass,
		"both":     compliancekit.StatusPass,
		"neither":  compliancekit.StatusFail,
		"offline":  compliancekit.StatusSkip,
	}
	for h, w := range want {
		if byHost[h] != w {
			t.Errorf("%s: %s, want %s", h, byHost[h], w)
		}
	}
}

func TestFirewallDefaultDeny(t *testing.T) {
	g := newGraph(t,
		hostWithAttrs("good", map[string]any{
			"firewall": map[string]any{"ufw_active": true, "ufw_default_incoming": "deny"},
		}),
		hostWithAttrs("loose", map[string]any{
			"firewall": map[string]any{"ufw_active": true, "ufw_default_incoming": "allow"},
		}),
		hostWithAttrs("nft", map[string]any{
			"firewall": map[string]any{"ufw_active": false, "nftables_active": true},
		}),
		hostWithAttrs("nothing", map[string]any{
			"firewall": map[string]any{"ufw_active": false, "nftables_active": false},
		}),
	)
	findings, err := FirewallDefaultDeny(context.Background(), g)
	if err != nil {
		t.Fatalf("FirewallDefaultDeny: %v", err)
	}
	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	want := map[string]compliancekit.Status{
		"good":    compliancekit.StatusPass,
		"loose":   compliancekit.StatusFail,
		"nft":     compliancekit.StatusSkip, // nft-only is intentionally Skipped at v0.2
		"nothing": compliancekit.StatusFail,
	}
	for h, w := range want {
		if byHost[h] != w {
			t.Errorf("%s: %s, want %s", h, byHost[h], w)
		}
	}
}

func TestAuditdRunning(t *testing.T) {
	g := newGraph(t,
		hostWithAttrs("running", map[string]any{
			"audit": map[string]any{"auditd_active": true},
		}),
		hostWithAttrs("off", map[string]any{
			"audit": map[string]any{"auditd_active": false},
		}),
		unreachableHost("offline", "x"),
	)
	findings, err := AuditdRunning(context.Background(), g)
	if err != nil {
		t.Fatalf("AuditdRunning: %v", err)
	}
	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	want := map[string]compliancekit.Status{
		"running": compliancekit.StatusPass,
		"off":     compliancekit.StatusFail,
		"offline": compliancekit.StatusSkip,
	}
	for h, w := range want {
		if byHost[h] != w {
			t.Errorf("%s: %s, want %s", h, byHost[h], w)
		}
	}
}

func TestJournaldPersistent(t *testing.T) {
	g := newGraph(t,
		hostWithAttrs("good", map[string]any{
			"audit": map[string]any{"journald_storage": "persistent"},
		}),
		hostWithAttrs("auto-default", map[string]any{
			"audit": map[string]any{"journald_storage": "auto"},
		}),
		hostWithAttrs("volatile", map[string]any{
			"audit": map[string]any{"journald_storage": "volatile"},
		}),
	)
	findings, err := JournaldPersistent(context.Background(), g)
	if err != nil {
		t.Fatalf("JournaldPersistent: %v", err)
	}
	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["good"] != compliancekit.StatusPass {
		t.Errorf("good: %s, want pass", byHost["good"])
	}
	if byHost["auto-default"] != compliancekit.StatusFail {
		t.Errorf("auto-default: %s, want fail (auto != persistent)", byHost["auto-default"])
	}
	if byHost["volatile"] != compliancekit.StatusFail {
		t.Errorf("volatile: %s, want fail", byHost["volatile"])
	}
}

func TestFirewallAuditChecks_RegisterIntoDefaultRegistry(t *testing.T) {
	for _, id := range []string{
		CheckFirewallActive.ID,
		CheckFirewallDefaultDeny.ID,
		CheckAuditdRunning.ID,
		CheckJournaldPersistent.ID,
	} {
		if _, ok := compliancekit.Lookup(id); !ok {
			t.Errorf("check %q not registered", id)
		}
	}
}
