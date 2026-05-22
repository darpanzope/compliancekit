package ui

import (
	"context"
	"strings"
	"testing"
)

// TestAuditChain_Intact verifies that consecutive AuditLog calls build
// a valid hash chain that VerifyAuditChain accepts.
func TestAuditChain_Intact(t *testing.T) {
	ctx := context.Background()
	u, _ := newUIForTests(t)
	u.AuditLog(ctx, "scan.trigger", "scan", "s-1", nil)
	u.AuditLog(ctx, "scan.trigger", "scan", "s-2", map[string]any{"provider": "aws"})
	u.AuditLog(ctx, "waiver.create", "waiver", "w-1", nil)

	res, err := u.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.Total != 3 {
		t.Errorf("total=%d want 3", res.Total)
	}
	if res.Chained != 3 {
		t.Errorf("chained=%d want 3", res.Chained)
	}
	if res.Unchained != 0 {
		t.Errorf("unchained=%d want 0", res.Unchained)
	}
	if len(res.Broken) != 0 {
		t.Errorf("broken=%v want []", res.Broken)
	}
}

// TestAuditChain_TamperDetected mutates a row's metadata after-the-
// fact and verifies the chain reports broken.
func TestAuditChain_TamperDetected(t *testing.T) {
	ctx := context.Background()
	u, st := newUIForTests(t)
	u.AuditLog(ctx, "scan.trigger", "scan", "s-1", nil)
	u.AuditLog(ctx, "scan.trigger", "scan", "s-2", nil)
	u.AuditLog(ctx, "scan.trigger", "scan", "s-3", nil)

	// Tamper: rewrite the middle row's metadata.
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE audit_log SET metadata_json = ? WHERE entity_id = ?`,
		`{"tampered":true}`, "s-2"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res, err := u.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if len(res.Broken) == 0 {
		t.Errorf("expected broken rows, got none")
	}
}

// TestLatestRowHashGenesis verifies that an empty audit_log returns
// the all-zero hash as the chain genesis.
func TestLatestRowHashGenesis(t *testing.T) {
	u, _ := newUIForTests(t)
	got := u.latestRowHash(context.Background())
	if got != strings.Repeat("0", 64) {
		t.Errorf("genesis prev_hash = %q, want 64 zeros", got)
	}
}
