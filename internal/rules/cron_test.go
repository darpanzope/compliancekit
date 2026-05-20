package rules

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// TestCronLoop_TickOnce dispatches when the cron next-run is in the
// past + skips when it isn't.
func TestCronLoop_TickOnce(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()

	var fired atomic.Int32
	reg.RegisterAction("count", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		fired.Add(1)
		return ActionResult{Outcome: "ok"}
	})

	rl := Rule{Rule: rsdk.Rule{
		Name:     "weekly-digest",
		Enabled:  true,
		Trigger:  rsdk.TriggerCron,
		CronExpr: "* * * * *", // every minute — guarantees a next-run ≤ now
		Timezone: "UTC",
		Actions:  []rsdk.Action{{Kind: "count"}},
	}}
	if _, err := repo.Create(context.Background(), rl); err != nil {
		t.Fatalf("Create: %v", err)
	}

	eng := New(repo, reg)
	loop := NewCronLoop(eng, repo, nil)
	loop.tickOnce(context.Background())

	if fired.Load() != 1 {
		t.Errorf("fired = %d, want 1", fired.Load())
	}

	// A second tick within the same minute should not fire again (the
	// MAX(triggered_at) now matches now, and the next computed run is
	// in the future).
	loop.tickOnce(context.Background())
	if fired.Load() != 1 {
		t.Errorf("after second tick fired = %d, want still 1", fired.Load())
	}
}

// TestCronLoop_InvalidCronExpr logs + skips without firing.
func TestCronLoop_InvalidCronExpr(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()
	var fired atomic.Int32
	reg.RegisterAction("count", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		fired.Add(1)
		return ActionResult{Outcome: "ok"}
	})
	rl := Rule{Rule: rsdk.Rule{
		Name: "bad-cron", Enabled: true,
		Trigger: rsdk.TriggerCron, CronExpr: "not a cron expr",
		Actions: []rsdk.Action{{Kind: "count"}},
	}}
	if _, err := repo.Create(context.Background(), rl); err != nil {
		t.Fatalf("Create: %v", err)
	}
	NewCronLoop(New(repo, reg), repo, nil).tickOnce(context.Background())
	if fired.Load() != 0 {
		t.Errorf("bad-cron fired = %d, want 0", fired.Load())
	}
}

// TestCronLoop_RunStopsOnContextCancel ensures the loop exits when
// the context is canceled.
func TestCronLoop_RunStopsOnContextCancel(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	loop := NewCronLoop(New(repo, NewRegistry()), repo, nil)
	loop.tickEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s of cancel")
	}
}
