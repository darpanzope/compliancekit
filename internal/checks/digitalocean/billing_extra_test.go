package digitalocean

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

func TestDropletStoppedTooLong(t *testing.T) {
	old := mkDroplet("old", map[string]any{
		"status":     "off",
		"created_at": time.Now().Add(-60 * 24 * time.Hour).UTC(),
	})
	young := mkDroplet("young", map[string]any{
		"status":     "off",
		"created_at": time.Now().Add(-7 * 24 * time.Hour).UTC(),
	})
	active := mkDroplet("active", map[string]any{
		"status":     "active",
		"created_at": time.Now().Add(-60 * 24 * time.Hour).UTC(),
	})
	g := newAccountGraph(old, young, active)
	findings, _ := DropletStoppedTooLong(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["old"] != core.StatusFail || by["young"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
	if _, exists := by["active"]; exists {
		t.Errorf("active droplet shouldn't produce a finding: %v", by["active"])
	}
}

func TestProjectPurpose(t *testing.T) {
	default1 := mkProj("d", map[string]any{"purpose": "Service or API"})
	empty := mkProj("e", map[string]any{"purpose": ""})
	custom := mkProj("c", map[string]any{"purpose": "Web Application"})
	g := newAccountGraph(default1, empty, custom)
	findings, _ := ProjectPurpose(context.Background(), g)
	by := map[string]core.Status{}
	for _, f := range findings {
		by[f.Resource.Name] = f.Status
	}
	if by["d"] != core.StatusFail || by["e"] != core.StatusFail || by["c"] != core.StatusPass {
		t.Errorf("statuses=%+v", by)
	}
}

func TestBillingManualVerifyChecks(t *testing.T) {
	g := newAccountGraph(mkAccount("acct", nil))
	cases := []struct {
		name string
		fn   func(context.Context, *core.ResourceGraph) ([]core.Finding, error)
		hint string
	}{
		{"alert review", checkFnFromID(t, "do-billing-monthly-alert-review"), "billing"},
		{"payment method", checkFnFromID(t, "do-billing-payment-method-valid"), "billing"},
		{"snapshot retention", checkFnFromID(t, "do-billing-snapshot-retention-policy"), "billing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, _ := c.fn(context.Background(), g)
			if len(findings) == 0 {
				t.Fatal("expected finding")
			}
			if findings[0].Status != core.StatusError {
				t.Errorf("status=%v want StatusError", findings[0].Status)
			}
			if !strings.Contains(strings.ToLower(findings[0].Message), c.hint) {
				t.Errorf("message %q missing %q", findings[0].Message, c.hint)
			}
		})
	}
}

// checkFnFromID looks up the registered CheckFunc by ID so the test
// table doesn't need to import each closure individually.
func checkFnFromID(t *testing.T, id string) func(context.Context, *core.ResourceGraph) ([]core.Finding, error) {
	t.Helper()
	fn, ok := core.Lookup(id)
	if !ok {
		t.Fatalf("no registered check %q", id)
	}
	return fn
}
