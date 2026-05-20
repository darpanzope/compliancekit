package expiry

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/rules"
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

func seedExpiredWaiver(t *testing.T, s *store.Store, id string, expiresAgo time.Duration) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().Add(-expiresAgo).UTC().Format(time.RFC3339)
	_, err := s.DB().ExecContext(context.Background(),
		`INSERT INTO waivers (id, check_id, resource_id, reason, approver, created_at, expires_at, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "ck.test", "res.x", "valid reason of sufficient length", "ops",
		now, expires, "active")
	if err != nil {
		t.Fatalf("seed waiver: %v", err)
	}
}

// TestExpiry_TickOnce revokes expired waivers + fires inbox + engine.
func TestExpiry_TickOnce(t *testing.T) {
	s := openTestStore(t)
	seedExpiredWaiver(t, s, "wv1", 1*time.Hour)
	seedExpiredWaiver(t, s, "wv2", 30*time.Minute)

	var inboxCalls atomic.Int32
	notify := func(_ context.Context, _, _, _, _, _ string) { inboxCalls.Add(1) }

	reg := rules.NewRegistry()
	var engineCalls atomic.Int32
	reg.RegisterAction("counter", func(_ context.Context, _ *rules.Rule, _ map[string]any, _ *rules.EvalContext) rules.ActionResult {
		engineCalls.Add(1)
		return rules.ActionResult{Outcome: "ok"}
	})
	// Add a rule that fires on every waiver.expired event so we can
	// verify the engine got called.
	repo := rules.NewRepo(s)
	_, err := repo.Create(context.Background(), rules.Rule{Rule: rsdk.Rule{
		Name: "expiry-action", Enabled: true,
		Trigger: rsdk.TriggerWaiverExpired,
		Actions: []rsdk.Action{{Kind: "counter"}},
	}})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	eng := rules.New(repo, reg)

	loop := New(eng, s, notify, nil)
	loop.tickOnce(context.Background())

	// Both expired waivers should be revoked.
	var revoked int
	_ = s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM waivers WHERE status = 'revoked'`).Scan(&revoked)
	if revoked != 2 {
		t.Errorf("revoked count = %d, want 2", revoked)
	}
	if inboxCalls.Load() != 2 {
		t.Errorf("inbox calls = %d, want 2", inboxCalls.Load())
	}
	if engineCalls.Load() != 2 {
		t.Errorf("engine calls = %d, want 2", engineCalls.Load())
	}

	// Second tick: nothing left to revoke.
	loop.tickOnce(context.Background())
	if inboxCalls.Load() != 2 {
		t.Errorf("after second tick inbox = %d, want still 2", inboxCalls.Load())
	}
}

// TestExpiry_RunStopsOnContextCancel exercises the goroutine
// lifecycle.
func TestExpiry_RunStopsOnContextCancel(t *testing.T) {
	s := openTestStore(t)
	loop := New(nil, s, nil, nil)
	loop.tickEvery = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
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
