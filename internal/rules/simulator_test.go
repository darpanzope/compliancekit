package rules

import (
	"context"
	"testing"
	"time"

	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// seedFinding inserts a row with a known created_at so the simulator
// window targets it deterministically.
func seedFinding(t *testing.T, repo *Repo, fp, severity string, createdAt time.Time) {
	t.Helper()
	// findings has a NOT NULL scan_id FK; create a placeholder scan
	// first if it doesn't exist.
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = repo.store.DB().ExecContext(context.Background(),
		`INSERT OR IGNORE INTO scans (id, created_at, source, status) VALUES (?, ?, ?, ?)`,
		"scan-sim", now, "cli", "completed")
	_, err := repo.store.DB().ExecContext(context.Background(),
		`INSERT INTO findings (id, scan_id, fingerprint, check_id, severity, status, provider,
		                       resource_id, resource_name, resource_type,
		                       first_seen_at, last_seen_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"f-"+fp, "scan-sim", fp, "iam.user.mfa", severity, "fail", "aws",
		"aws.iam.user.x", "x", "aws.iam.user",
		createdAt.Format(time.RFC3339), createdAt.Format(time.RFC3339),
		createdAt.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

// TestSimulate_WindowRespected verifies the simulator only considers
// findings in [Start, End].
func TestSimulate_WindowRespected(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()
	reg.RegisterCondition("always", func(_ context.Context, _ map[string]any, _ *EvalContext) (bool, error) {
		return true, nil
	})
	reg.RegisterAction("noop", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		return ActionResult{Outcome: "ok"}
	})

	// Two findings: one inside the window, one outside.
	now := time.Now().UTC()
	seedFinding(t, repo, "in-window", "high", now.Add(-5*24*time.Hour))
	seedFinding(t, repo, "out-window", "high", now.Add(-100*24*time.Hour))

	// A rule that always matches.
	if _, err := repo.Create(context.Background(), Rule{Rule: rsdk.Rule{
		Name: "any", Enabled: true,
		Trigger:   rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{Term: &rsdk.Term{Kind: "always"}},
		Actions:   []rsdk.Action{{Kind: "noop"}},
	}}); err != nil {
		t.Fatalf("Create rule: %v", err)
	}

	eng := New(repo, reg)
	got, err := eng.Simulate(context.Background(), SimulateOptions{
		Start: now.Add(-30 * 24 * time.Hour),
		End:   now,
	})
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("results = %d, want 1", len(got))
	}
	if got[0].WouldFire != 1 {
		t.Errorf("WouldFire = %d, want 1 (only in-window finding)", got[0].WouldFire)
	}
}

// TestSimulate_DoesNotDispatch confirms the simulator never invokes
// real actions even when the rule has a dispatch-side-effect action.
func TestSimulate_DoesNotDispatch(t *testing.T) {
	s := openTestStore(t)
	repo := NewRepo(s)
	reg := NewRegistry()
	var realFired int
	reg.RegisterCondition("always", func(_ context.Context, _ map[string]any, _ *EvalContext) (bool, error) {
		return true, nil
	})
	reg.RegisterAction("count", func(_ context.Context, _ *Rule, _ map[string]any, _ *EvalContext) ActionResult {
		realFired++
		return ActionResult{Outcome: "ok"}
	})
	seedFinding(t, repo, "f1", "high", time.Now().Add(-1*24*time.Hour).UTC())
	if _, err := repo.Create(context.Background(), Rule{Rule: rsdk.Rule{
		Name: "sim", Enabled: true,
		Trigger:   rsdk.TriggerFindingCreated,
		Condition: rsdk.Condition{Term: &rsdk.Term{Kind: "always"}},
		Actions:   []rsdk.Action{{Kind: "count"}},
	}}); err != nil {
		t.Fatalf("Create rule: %v", err)
	}

	if _, err := New(repo, reg).Simulate(context.Background(), SimulateOptions{}); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if realFired != 0 {
		t.Errorf("realFired = %d, want 0 (simulator must not dispatch)", realFired)
	}
	// rule_runs row should be simulated=1.
	var sim int
	_ = s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM rule_runs WHERE simulated = 1`).Scan(&sim)
	if sim < 1 {
		t.Errorf("simulated rows = %d, want ≥1", sim)
	}
}
