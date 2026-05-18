package digitalocean

import (
	"context"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 1 — table-driven tests for the 10 account-governance
// checks introduced in account_extra.go. Each check has at least one
// pass + one fail (or status=error for manual-verify) case.

func TestAccountStatusMessageClean(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want compliancekit.Status
	}{
		{"empty", "", compliancekit.StatusPass},
		{"whitespace", "   ", compliancekit.StatusPass},
		{"flagged", "billing arrears — payment failed", compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newAccountGraph(mkAccount("a", map[string]any{"status_message": c.msg}))
			findings, _ := AccountStatusMessageClean(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("findings=%d, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v (msg=%q)", findings[0].Status, c.want, c.msg)
			}
		})
	}
}

func TestAccountDropletQuotaHeadroom(t *testing.T) {
	cases := []struct {
		name    string
		limit   int
		droplet int
		want    compliancekit.Status
	}{
		{"unbounded", 0, 100, compliancekit.StatusSkip},
		{"half-used", 25, 12, compliancekit.StatusPass},
		{"at-threshold", 25, 20, compliancekit.StatusPass}, // 80% exactly = pass
		{"over-threshold", 25, 21, compliancekit.StatusFail},
		{"saturated", 25, 25, compliancekit.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resources := []compliancekit.Resource{mkAccount("a", map[string]any{"droplet_limit": c.limit})}
			for i := 0; i < c.droplet; i++ {
				resources = append(resources, mkDroplet("d"+itoaSimple(i), nil))
			}
			g := newAccountGraph(resources...)
			findings, _ := AccountDropletQuotaHeadroom(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("findings=%d, want 1", len(findings))
			}
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v", findings[0].Status, c.want)
			}
		})
	}
}

func TestAccountVolumeQuotaHeadroom(t *testing.T) {
	g := newAccountGraph(
		mkAccount("a", map[string]any{"volume_limit": 10}),
		mkVolume("v1", nil), mkVolume("v2", nil), mkVolume("v3", nil),
		mkVolume("v4", nil), mkVolume("v5", nil), mkVolume("v6", nil),
		mkVolume("v7", nil), mkVolume("v8", nil), mkVolume("v9", nil),
	) // 9/10 = 90% > threshold
	findings, _ := AccountVolumeQuotaHeadroom(context.Background(), g)
	if findings[0].Status != compliancekit.StatusFail {
		t.Errorf("9/10 should fail, got %v", findings[0].Status)
	}
}

func TestAccountReservedIPQuotaHeadroom(t *testing.T) {
	g := newAccountGraph(
		mkAccount("a", map[string]any{"reserved_ip_limit": 5}),
		mkRIP("ip1", nil), mkRIP("ip2", nil), // 2/5 = 40% → pass
	)
	findings, _ := AccountReservedIPQuotaHeadroom(context.Background(), g)
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("2/5 should pass, got %v", findings[0].Status)
	}
}

func TestAccountMonitoringAlertCoverage(t *testing.T) {
	t.Run("all four covered", func(t *testing.T) {
		g := newAccountGraph(
			mkAccount("a", nil),
			mkAlert("cpu", map[string]any{"alert_type": "v1/insights/droplet/cpu", "enabled": true}),
			mkAlert("mem", map[string]any{"alert_type": "v1/insights/droplet/memory_utilization_percent", "enabled": true}),
			mkAlert("disk", map[string]any{"alert_type": "v1/insights/droplet/disk_utilization_percent", "enabled": true}),
			mkAlert("load", map[string]any{"alert_type": "v1/insights/droplet/load_5", "enabled": true}),
		)
		findings, _ := AccountMonitoringAlertCoverage(context.Background(), g)
		if findings[0].Status != compliancekit.StatusPass {
			t.Errorf("got %v, want pass", findings[0].Status)
		}
	})
	t.Run("missing memory + load", func(t *testing.T) {
		g := newAccountGraph(
			mkAccount("a", nil),
			mkAlert("cpu", map[string]any{"alert_type": "v1/insights/droplet/cpu", "enabled": true}),
			mkAlert("disk", map[string]any{"alert_type": "v1/insights/droplet/disk_utilization_percent", "enabled": true}),
		)
		findings, _ := AccountMonitoringAlertCoverage(context.Background(), g)
		if findings[0].Status != compliancekit.StatusFail {
			t.Fatalf("got %v, want fail", findings[0].Status)
		}
		if !strings.Contains(findings[0].Message, "memory") || !strings.Contains(findings[0].Message, "load") {
			t.Errorf("missing categories should mention memory + load: %q", findings[0].Message)
		}
	})
	t.Run("disabled alert does not count", func(t *testing.T) {
		g := newAccountGraph(
			mkAccount("a", nil),
			mkAlert("cpu-disabled", map[string]any{"alert_type": "v1/insights/droplet/cpu", "enabled": false}),
		)
		findings, _ := AccountMonitoringAlertCoverage(context.Background(), g)
		if findings[0].Status != compliancekit.StatusFail {
			t.Errorf("disabled alert should not count, got %v", findings[0].Status)
		}
	})
}

// ----- manual-verify checks: status is always StatusError, message
// references the dashboard URL. ----------------------------------------

func TestAccountManualVerifyChecks(t *testing.T) {
	g := newAccountGraph(mkAccount("a", nil))

	cases := []struct {
		name string
		fn   func(context.Context, *compliancekit.ResourceGraph) ([]compliancekit.Finding, error)
		url  string
	}{
		{"mfa", AccountMFARequired, "/account/security"},
		{"token-rotation", AccountAPITokenRotation, "/account/api/tokens"},
		{"audit-log", AccountAuditLogRetention, "/account/audit-logs"},
		{"billing-alerts", AccountBillingAlertThresholds, "/account/billing"},
		{"owner-delegation", AccountOwnerDelegation, "/account/team"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), g)
			if len(findings) != 1 {
				t.Fatalf("findings=%d, want 1", len(findings))
			}
			if findings[0].Status != compliancekit.StatusError {
				t.Errorf("manual-verify must use StatusError; got %v", findings[0].Status)
			}
			if !strings.Contains(findings[0].Message, c.url) {
				t.Errorf("message must reference dashboard %q; got %q", c.url, findings[0].Message)
			}
		})
	}
}

// itoaSimple converts small ints to string without importing strconv
// at the top of the fixture file (keeps the imports list short).
// Sufficient for the 0–25 range tests use.
func itoaSimple(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+(i%10))) + out
		i /= 10
	}
	return out
}
