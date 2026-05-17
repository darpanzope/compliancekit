package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 11 — coverage for the audit-rule-presence framework.

func hostWithAuditRules(name string, rules []string) core.Resource {
	return core.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable": true,
			"audit": map[string]any{
				"audit_rules": rules,
			},
		},
	}
}

func TestAuditRuleChecks(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		rules []string
		want  core.Status
	}{
		{
			name:  "passwd watch present → pass",
			id:    "linux-audit-rule-passwd",
			rules: []string{"-w /etc/passwd -p wa -k identity"},
			want:  core.StatusPass,
		},
		{
			name:  "passwd watch absent → fail",
			id:    "linux-audit-rule-passwd",
			rules: []string{"-w /etc/shadow -p wa -k identity"},
			want:  core.StatusFail,
		},
		{
			name: "time-change rule with reordered -F flags → pass (fuzzy substring match)",
			id:   "linux-audit-rule-time-change",
			rules: []string{
				"-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change",
				"-a always,exit -F arch=b32 -S adjtimex -k time-change",
			},
			want: core.StatusPass,
		},
		{
			name:  "shadow watch present → pass",
			id:    "linux-audit-rule-shadow",
			rules: []string{"-w /etc/shadow -p wa -k identity"},
			want:  core.StatusPass,
		},
		{
			name:  "sudoers watch absent → fail",
			id:    "linux-audit-rule-sudoers",
			rules: []string{"-w /etc/passwd -p wa -k identity"},
			want:  core.StatusFail,
		},
		{
			name:  "no rules loaded → fail",
			id:    "linux-audit-rule-passwd",
			rules: []string{},
			want:  core.StatusFail,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraph(t, hostWithAuditRules("h", c.rules))
			fn, ok := core.Lookup(c.id)
			if !ok {
				t.Fatalf("check %q not registered", c.id)
			}
			findings, _ := fn(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("status=%v want %v (id=%s)", findings[0].Status, c.want, c.id)
			}
		})
	}
}

func TestAuditRuleChecks_SkipsWhenAuditAttrMissing(t *testing.T) {
	g := newGraph(t, core.Resource{
		ID: "linux.host.h", Type: linuxcol.HostType, Name: "h", Provider: "linux",
		Attributes: map[string]any{"reachable": true},
	})
	fn, _ := core.Lookup("linux-audit-rule-passwd")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != core.StatusSkip {
		t.Errorf("status=%v want StatusSkip when audit attr absent", findings[0].Status)
	}
}

func TestAuditRuleChecks_SkipsWhenUnreachable(t *testing.T) {
	g := newGraph(t, unreachableHost("offline", "i/o timeout"))
	fn, _ := core.Lookup("linux-audit-rule-passwd")
	findings, _ := fn(context.Background(), g)
	if findings[0].Status != core.StatusSkip {
		t.Errorf("status=%v want StatusSkip when host unreachable", findings[0].Status)
	}
}
