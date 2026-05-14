package diff

import (
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/core"
)

func mkFinding(checkID, resID string, status core.Status, sev core.Severity) core.Finding {
	return core.Finding{
		CheckID:  checkID,
		Status:   status,
		Severity: sev,
		Resource: core.ResourceRef{
			ID:       resID,
			Type:     "digitalocean.droplet",
			Name:     resID,
			Provider: "digitalocean",
		},
	}
}

func TestCompute_NewExistingResolved(t *testing.T) {
	// Baseline: 2 findings.
	b := baseline.Capture([]core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusFail, core.SeverityMedium),
	}, time.Now())

	// Current scan: same 'a' still failing, 'b' is gone (resolved),
	// 'c' is brand new.
	current := []core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
		mkFinding("c", "r3", core.StatusFail, core.SeverityCritical),
	}

	r := Compute(b, current)

	if len(r.New) != 1 || r.New[0].CheckID != "c" {
		t.Errorf("New: got %+v, want one entry for c", r.New)
	}
	if len(r.Existing) != 1 || r.Existing[0].CheckID != "a" {
		t.Errorf("Existing: got %+v, want one entry for a", r.Existing)
	}
	if len(r.Resolved) != 1 || r.Resolved[0].CheckID != "b" {
		t.Errorf("Resolved: got %+v, want one entry for b", r.Resolved)
	}
}

func TestCompute_NoChange(t *testing.T) {
	in := []core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusPass, core.SeverityLow),
	}
	b := baseline.Capture(in, time.Now())
	r := Compute(b, in)

	if len(r.New) != 0 {
		t.Errorf("New should be empty, got %+v", r.New)
	}
	if len(r.Existing) != 2 {
		t.Errorf("Existing: got %d, want 2", len(r.Existing))
	}
	if len(r.Resolved) != 0 {
		t.Errorf("Resolved should be empty, got %+v", r.Resolved)
	}
}

func TestCompute_StatusChangeRegistersAsNew(t *testing.T) {
	// Same check + resource but the status changed (Pass -> Fail).
	// Because Fingerprint includes status, the new fingerprint
	// doesn't match the baseline -> registers as New + Resolved.
	b := baseline.Capture([]core.Finding{
		mkFinding("a", "r1", core.StatusPass, core.SeverityHigh),
	}, time.Now())

	current := []core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
	}
	r := Compute(b, current)

	if len(r.New) != 1 || r.New[0].Status != core.StatusFail {
		t.Errorf("status change should produce a New entry, got %+v", r.New)
	}
	if len(r.Resolved) != 1 || r.Resolved[0].Status != core.StatusPass {
		t.Errorf("status change should produce a Resolved entry, got %+v", r.Resolved)
	}
}

func TestCompute_DedupCurrent(t *testing.T) {
	// Same finding three times (would happen if multiple frameworks
	// reference it). Should count once.
	f := mkFinding("a", "r1", core.StatusFail, core.SeverityHigh)
	b := baseline.Capture(nil, time.Now())
	r := Compute(b, []core.Finding{f, f, f})

	if len(r.New) != 1 {
		t.Errorf("dedup failed: got %d new, want 1", len(r.New))
	}
}

func TestHasNewAtOrAbove(t *testing.T) {
	b := baseline.Capture(nil, time.Now())
	r := Compute(b, []core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityMedium),
		mkFinding("b", "r2", core.StatusFail, core.SeverityHigh),
	})

	if !r.HasNewAtOrAbove(core.SeverityHigh) {
		t.Error("HasNewAtOrAbove(high) should be true")
	}
	if r.HasNewAtOrAbove(core.SeverityCritical) {
		t.Error("HasNewAtOrAbove(critical) should be false")
	}
	if !r.HasNewAtOrAbove(core.SeverityInfo) {
		t.Error("HasNewAtOrAbove(info) should be true (anything actionable)")
	}
}

func TestHasNewAtOrAbove_IgnoresPassesAndSkips(t *testing.T) {
	b := baseline.Capture(nil, time.Now())
	r := Compute(b, []core.Finding{
		mkFinding("a", "r1", core.StatusPass, core.SeverityCritical),
		mkFinding("b", "r2", core.StatusSkip, core.SeverityCritical),
	})
	if r.HasNewAtOrAbove(core.SeverityHigh) {
		t.Error("pass/skip findings should not trigger fail-on-new")
	}
}

func TestScoreDelta(t *testing.T) {
	old := []core.Finding{
		mkFinding("a", "r1", core.StatusPass, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusFail, core.SeverityHigh),
	}
	b := baseline.Capture(old, time.Now()) // score 50

	// b is now passing too -> score should go up to 100.
	current := []core.Finding{
		mkFinding("a", "r1", core.StatusPass, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusPass, core.SeverityHigh),
	}
	r := Compute(b, current)
	if r.PreviousScore != 50 || r.CurrentScore != 100 {
		t.Errorf("score delta: prev=%d curr=%d, want 50/100", r.PreviousScore, r.CurrentScore)
	}
}

func TestSeverityCounts(t *testing.T) {
	in := []core.Finding{
		mkFinding("a", "r1", core.StatusFail, core.SeverityHigh),
		mkFinding("b", "r2", core.StatusFail, core.SeverityHigh),
		mkFinding("c", "r3", core.StatusFail, core.SeverityMedium),
	}
	counts := CountsBySeverity(in)
	if counts["high"] != 2 || counts["medium"] != 1 {
		t.Errorf("counts: got %+v, want high=2 medium=1", counts)
	}
}
