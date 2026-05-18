package linux

import (
	"context"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 11 — coverage for the sshd-deepening framework. One
// row per sshdCmp variant + a skip-on-missing case exercises every
// branch in sshdEvaluate and sshdCheckFunc.

func TestSSHDExtraChecks(t *testing.T) {
	cases := []struct {
		name string
		id   string
		key  string
		val  string
		want compliancekit.Status
	}{
		// eq-no
		{"permit-empty-passwords=no → pass", "linux-sshd-permit-empty-passwords", "permitemptypasswords", "no", compliancekit.StatusPass},
		{"permit-empty-passwords=yes → fail", "linux-sshd-permit-empty-passwords", "permitemptypasswords", "yes", compliancekit.StatusFail},
		// eq-yes
		{"ignore-rhosts=yes → pass", "linux-sshd-ignore-rhosts", "ignorerhosts", "yes", compliancekit.StatusPass},
		{"ignore-rhosts=no → fail", "linux-sshd-ignore-rhosts", "ignorerhosts", "no", compliancekit.StatusFail},
		// lte-int (in range)
		{"client-alive-interval=300 → pass (boundary)", "linux-sshd-client-alive-interval", "clientaliveinterval", "300", compliancekit.StatusPass},
		{"client-alive-interval=150 → pass", "linux-sshd-client-alive-interval", "clientaliveinterval", "150", compliancekit.StatusPass},
		{"client-alive-interval=600 → fail (above ceiling)", "linux-sshd-client-alive-interval", "clientaliveinterval", "600", compliancekit.StatusFail},
		{"client-alive-interval=0 → fail (must be > 0)", "linux-sshd-client-alive-interval", "clientaliveinterval", "0", compliancekit.StatusFail},
		{"client-alive-interval=NaN → fail (not integer)", "linux-sshd-client-alive-interval", "clientaliveinterval", "lots", compliancekit.StatusFail},
		// eq-string with Banner (exact match required)
		{"banner=/etc/issue.net → pass", "linux-sshd-banner-set", "banner", "/etc/issue.net", compliancekit.StatusPass},
		{"banner=none → fail", "linux-sshd-banner-set", "banner", "none", compliancekit.StatusFail},
		// eq-string with LogLevel (info OR verbose accepted)
		{"loglevel=VERBOSE → pass", "linux-sshd-loglevel-info-or-verbose", "loglevel", "VERBOSE", compliancekit.StatusPass},
		{"loglevel=INFO → pass (also acceptable)", "linux-sshd-loglevel-info-or-verbose", "loglevel", "INFO", compliancekit.StatusPass},
		{"loglevel=QUIET → fail", "linux-sshd-loglevel-info-or-verbose", "loglevel", "QUIET", compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, hostWithSSHD("h", map[string]string{c.key: c.val}))
			fn, ok := compliancekit.Lookup(c.id)
			if !ok {
				t.Fatalf("check %q not registered", c.id)
			}
			findings, _ := fn(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (id=%s val=%q)", findings[0].Status, c.want, c.id, c.val)
			}
		})
	}
}

func TestSSHDExtraChecks_SkipsWhenConfigMissing(t *testing.T) {
	g := newGraph(t, unreachableHost("offline", "i/o timeout"))
	fn, _ := compliancekit.Lookup("linux-sshd-permit-empty-passwords")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != compliancekit.StatusSkip {
		t.Errorf("status=%v want StatusSkip", findings[0].Status)
	}
}

func TestSSHDSpecsCoverage(t *testing.T) {
	if len(sshdSpecs) < 10 {
		t.Errorf("sshdSpecs=%d entries; phase 6 expects ≥10", len(sshdSpecs))
	}
	seen := map[string]bool{}
	for _, s := range sshdSpecs {
		if seen[s.id] {
			t.Errorf("duplicate sshd spec id: %s", s.id)
		}
		seen[s.id] = true
		if s.key == "" || s.severity == 0 || s.cmp == "" {
			t.Errorf("incomplete sshd spec: %+v", s)
		}
	}
}
