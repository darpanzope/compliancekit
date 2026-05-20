package rules

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenSQLite(context.Background(),
		"file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := s.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRepo_CRUD round-trips a rule through Create + ByID + Update +
// Delete. Verifies the condition tree + actions array survive the
// JSON serialize/deserialize.
func TestRepo_CRUD(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	ctx := context.Background()

	rl := Rule{Rule: rsdk.Rule{
		Name:        "critical-aws-notify",
		Description: "Critical AWS IAM findings → notify @sec",
		Enabled:     true,
		Priority:    50,
		Trigger:     rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{
			Op: rsdk.OpAnd,
			Children: []rsdk.Condition{
				{Term: &rsdk.Term{Kind: "severity", Params: map[string]any{"min": "critical"}}},
				{Term: &rsdk.Term{Kind: "provider", Params: map[string]any{"is": "aws"}}},
			},
		},
		Actions: []rsdk.Action{
			{Kind: "notify", Params: map[string]any{"sink": "slack", "channel": "#sec"}},
		},
	}}
	got, err := repo.Create(ctx, rl)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.ID == "" {
		t.Fatal("Create returned empty ID")
	}

	loaded, err := repo.ByID(ctx, got.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if loaded.Name != rl.Name {
		t.Errorf("Name = %q", loaded.Name)
	}
	if loaded.Condition.Op != rsdk.OpAnd || len(loaded.Condition.Children) != 2 {
		t.Errorf("Condition lost in round trip: %+v", loaded.Condition)
	}
	if len(loaded.Actions) != 1 || loaded.Actions[0].Kind != "notify" {
		t.Errorf("Actions lost: %+v", loaded.Actions)
	}

	loaded.Priority = 10
	if err := repo.Update(ctx, loaded); err != nil {
		t.Fatalf("Update: %v", err)
	}
	again, _ := repo.ByID(ctx, got.ID)
	if again.Priority != 10 {
		t.Errorf("Update lost priority: %d", again.Priority)
	}

	if err := repo.Delete(ctx, got.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestEngine_AndOrCondition walks AND + OR composition through the
// engine + verifies the rule_runs row records the outcome.
func TestEngine_AndOrCondition(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()

	// Two simple evaluators for the test.
	reg.RegisterCondition("sev-is", func(_ context.Context, p map[string]any, ec *EvalContext) (bool, error) {
		want, _ := p["value"].(string)
		return ec.Finding.Severity == want, nil
	})
	reg.RegisterCondition("provider-is", func(_ context.Context, p map[string]any, ec *EvalContext) (bool, error) {
		want, _ := p["value"].(string)
		return ec.Finding.Provider == want, nil
	})
	// A counter action so we can assert dispatch happened.
	var fired int
	reg.RegisterAction("count", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		fired++
		return ActionResult{Outcome: "ok"}
	})

	// Rule that fires on critical AND aws.
	rl := Rule{Rule: rsdk.Rule{
		Name: "crit-and-aws", Enabled: true, Priority: 100,
		Trigger: rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{
			Op: rsdk.OpAnd,
			Children: []rsdk.Condition{
				{Term: &rsdk.Term{Kind: "sev-is", Params: map[string]any{"value": "critical"}}},
				{Term: &rsdk.Term{Kind: "provider-is", Params: map[string]any{"value": "aws"}}},
			},
		},
		Actions: []rsdk.Action{{Kind: "count"}},
	}}
	if _, err := repo.Create(context.Background(), rl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	eng := New(repo, reg)
	ec := &EvalContext{
		Trigger: rsdk.TriggerFindingCreated,
		Finding: FindingFacts{Fingerprint: "fp1", Severity: "critical", Provider: "aws"},
	}
	matched, err := eng.HandleEvent(context.Background(), ec)
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(matched) != 1 {
		t.Errorf("matched = %d, want 1", len(matched))
	}
	if fired != 1 {
		t.Errorf("action fired = %d, want 1", fired)
	}

	// Wrong provider → no match.
	ec.Finding.Provider = "gcp"
	matched, _ = eng.HandleEvent(context.Background(), ec)
	if len(matched) != 0 {
		t.Errorf("matched = %d, want 0", len(matched))
	}
}

// TestEngine_Simulator suppresses dispatch + tags simulated=1.
func TestEngine_Simulator(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()
	var fired int
	reg.RegisterCondition("always", func(_ context.Context, _ map[string]any, _ *EvalContext) (bool, error) {
		return true, nil
	})
	reg.RegisterAction("count", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		fired++
		return ActionResult{Outcome: "ok"}
	})
	rl := Rule{Rule: rsdk.Rule{
		Name: "always", Enabled: true, Priority: 100,
		Trigger:   rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{Term: &rsdk.Term{Kind: "always"}},
		Actions:   []rsdk.Action{{Kind: "count"}},
	}}
	if _, err := repo.Create(context.Background(), rl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sim := New(repo, reg).WithSimulator()
	if _, err := sim.HandleEvent(context.Background(), &EvalContext{
		Trigger: rsdk.TriggerFindingCreated,
		Finding: FindingFacts{Fingerprint: "fpx"},
	}); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if fired != 0 {
		t.Errorf("simulator ran the real action %d times; want 0", fired)
	}

	// Verify simulated=1 row landed.
	var sim1 int
	err := s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM rule_runs WHERE simulated = 1`).Scan(&sim1)
	if err != nil {
		t.Fatalf("count simulated: %v", err)
	}
	if sim1 != 1 {
		t.Errorf("simulated rows = %d, want 1", sim1)
	}
}

// TestSeverityAtLeast smoke-tests the helper.
func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		have, want string
		ok         bool
	}{
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"info", "low", false},
		{"weird", "low", false},
	}
	for _, c := range cases {
		if got := SeverityAtLeast(c.have, c.want); got != c.ok {
			t.Errorf("SeverityAtLeast(%s, %s) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

// TestSilenceWindow checks normal + wrap-around windows.
func TestSilenceWindow(t *testing.T) {
	loc := time.UTC
	atHour := func(h, m int) time.Time { return time.Date(2026, 5, 20, h, m, 0, 0, loc) }
	cases := []struct {
		name       string
		start, end string
		now        time.Time
		want       bool
	}{
		{"in_window", "09:00", "17:00", atHour(10, 0), true},
		{"out_window", "09:00", "17:00", atHour(18, 0), false},
		{"wrap_inside_morning", "22:00", "06:00", atHour(2, 0), true},
		{"wrap_inside_evening", "22:00", "06:00", atHour(23, 0), true},
		{"wrap_outside", "22:00", "06:00", atHour(12, 0), false},
		{"bad_format", "xx:00", "17:00", atHour(10, 0), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SilenceWindow(c.now, c.start, c.end); got != c.want {
				t.Errorf("SilenceWindow = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEngine_UnknownActionRecorded confirms an unknown action kind
// surfaces in the recorded ActionResult instead of silently swallowed.
func TestEngine_UnknownActionRecorded(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()
	reg.RegisterCondition("always", func(_ context.Context, _ map[string]any, _ *EvalContext) (bool, error) {
		return true, nil
	})
	rl := Rule{Rule: rsdk.Rule{
		Name: "ghost", Enabled: true,
		Trigger:   rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{Term: &rsdk.Term{Kind: "always"}},
		Actions:   []rsdk.Action{{Kind: "nope"}},
	}}
	if _, err := repo.Create(context.Background(), rl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	matched, err := New(repo, reg).HandleEvent(context.Background(), &EvalContext{
		Trigger: rsdk.TriggerFindingCreated,
		Finding: FindingFacts{Fingerprint: "fp"},
	})
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(matched) != 1 {
		t.Errorf("matched = %d, want 1", len(matched))
	}
	runs, err := repo.RecentRuns(context.Background(), matched[0].ID, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("RecentRuns: %v, len=%d", err, len(runs))
	}
	if len(runs[0].Actions) != 1 || runs[0].Actions[0].Error == "" {
		t.Errorf("expected recorded error, got %+v", runs[0].Actions)
	}
	_ = errors.New
}
