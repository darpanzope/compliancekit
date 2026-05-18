package linux

import (
	"context"
	"strings"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 2 — table-driven test for the sysctl framework. One
// canonical pass + fail + skip case per comparison operator covers
// every sysctl-shaped check by induction; per-key coverage comes
// from per-distro fixtures in Phase 11.

func sysctlHost(name string, sysctls map[string]int) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable": true,
			"kernel": map[string]any{
				"sysctls": sysctls,
			},
		},
	}
}

func TestSysctlChecks_PassFailSkip(t *testing.T) {
	// Pick three representative specs to exercise:
	//   - cmpEq with want=1 (tcp_syncookies)
	//   - cmpEq with want=0 (ip_forward)
	//   - cmpGte with want=1 (kptr_restrict — actual want is 2 per spec)
	cases := []struct {
		name string
		id   string
		key  string
		val  int
		want compliancekit.Status
	}{
		{"tcp_syncookies=1 → pass", "linux-sysctl-tcp-syncookies", "net.ipv4.tcp_syncookies", 1, compliancekit.StatusPass},
		{"tcp_syncookies=0 → fail", "linux-sysctl-tcp-syncookies", "net.ipv4.tcp_syncookies", 0, compliancekit.StatusFail},
		{"ip_forward=0 → pass", "linux-sysctl-ip-forward-disabled", "net.ipv4.ip_forward", 0, compliancekit.StatusPass},
		{"ip_forward=1 → fail", "linux-sysctl-ip-forward-disabled", "net.ipv4.ip_forward", 1, compliancekit.StatusFail},
		{"kptr_restrict=2 → pass (gte)", "linux-sysctl-kptr-restrict", "kernel.kptr_restrict", 2, compliancekit.StatusPass},
		{"kptr_restrict=1 → pass (gte boundary)", "linux-sysctl-kptr-restrict", "kernel.kptr_restrict", 1, compliancekit.StatusPass},
		{"kptr_restrict=0 → fail", "linux-sysctl-kptr-restrict", "kernel.kptr_restrict", 0, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, sysctlHost("h", map[string]int{c.key: c.val}))
			fn, ok := compliancekit.Lookup(c.id)
			if !ok {
				t.Fatalf("check %q not registered", c.id)
			}
			findings, _ := fn(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (id=%s val=%d)", findings[0].Status, c.want, c.id, c.val)
			}
		})
	}
}

func TestSysctlChecks_SkipsWhenKeyAbsent(t *testing.T) {
	g := newGraph(t, sysctlHost("h", map[string]int{"some.other.key": 1}))
	fn, _ := compliancekit.Lookup("linux-sysctl-tcp-syncookies")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != compliancekit.StatusSkip {
		t.Errorf("status=%v want StatusSkip when sysctl key not surfaced", findings[0].Status)
	}
	if !strings.Contains(findings[0].Message, "unavailable") {
		t.Errorf("message should mention unavailable: %q", findings[0].Message)
	}
}

func TestSysctlChecks_ErrorWhenKernelMissing(t *testing.T) {
	hostNoKernel := compliancekit.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	}
	g := newGraph(t, hostNoKernel)
	fn, _ := compliancekit.Lookup("linux-sysctl-tcp-syncookies")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != compliancekit.StatusError {
		t.Errorf("status=%v want StatusError when kernel attr missing", findings[0].Status)
	}
}

func TestSysctlSpecsCoverage(t *testing.T) {
	if len(sysctlSpecs) < 25 {
		t.Errorf("sysctlSpecs=%d entries; v0.20 phase 2 expects ≥25", len(sysctlSpecs))
	}
	seen := map[string]bool{}
	for _, s := range sysctlSpecs {
		if seen[s.id] {
			t.Errorf("duplicate sysctl spec id: %s", s.id)
		}
		seen[s.id] = true
		if s.key == "" || s.severity == 0 || len(s.cis) == 0 {
			t.Errorf("incomplete sysctl spec: %+v", s)
		}
	}
}
