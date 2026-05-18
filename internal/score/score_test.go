package score

import (
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkFinding(status compliancekit.Status, sev compliancekit.Severity) compliancekit.Finding {
	return compliancekit.Finding{Status: status, Severity: sev}
}

func TestCompute_EmptyInput(t *testing.T) {
	r := Compute(nil)
	if r.Score != 100 || r.Coverage != 100 {
		t.Errorf("empty input: got Score=%d Coverage=%d, want 100/100", r.Score, r.Coverage)
	}
	if r.Total != 0 || r.Passing != 0 || r.Failing != 0 || r.Errored != 0 || r.Skipped != 0 {
		t.Errorf("empty input should have zero weights, got %+v", r)
	}
}

func TestCompute_AllPass(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityCritical),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityLow),
	}
	r := Compute(in)
	if r.Score != 100 {
		t.Errorf("all pass: Score=%d, want 100", r.Score)
	}
	if r.Failing != 0 || r.Errored != 0 {
		t.Errorf("all pass: failing/errored should be 0, got Failing=%d Errored=%d", r.Failing, r.Errored)
	}
}

func TestCompute_AllFail(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityCritical),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityLow),
	}
	r := Compute(in)
	if r.Score != 0 {
		t.Errorf("all fail: Score=%d, want 0", r.Score)
	}
	if r.Passing != 0 {
		t.Errorf("all fail: passing should be 0, got %d", r.Passing)
	}
}

func TestCompute_HalfPassHalfFail_SameSeverity(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
	}
	r := Compute(in)
	if r.Score != 50 {
		t.Errorf("half/half same severity: Score=%d, want 50", r.Score)
	}
}

func TestCompute_OneCriticalDominatesManyLow(t *testing.T) {
	// 1 critical fail (weight 50) against 10 low passes (weight 30)
	// → passing/total = 30 / 80 = 37.5 → 38 (round-half-up)
	in := []compliancekit.Finding{mkFinding(compliancekit.StatusFail, compliancekit.SeverityCritical)}
	for i := 0; i < 10; i++ {
		in = append(in, mkFinding(compliancekit.StatusPass, compliancekit.SeverityLow))
	}
	r := Compute(in)
	if r.Score != 38 {
		t.Errorf("critical dominates: Score=%d, want 38", r.Score)
	}
}

func TestCompute_SkipsExcludedFromScore(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusSkip, compliancekit.SeverityCritical), // would drag if counted
		mkFinding(compliancekit.StatusSkip, compliancekit.SeverityCritical),
	}
	r := Compute(in)
	if r.Score != 50 {
		t.Errorf("skips excluded: Score=%d, want 50 (skips not in numerator/denominator)", r.Score)
	}
	if r.Skipped != 100 {
		t.Errorf("skipped weight: got %d, want 100", r.Skipped)
	}
	// Coverage: total=40 (20+20), skipped=100, coverage = 40/140 = 28.57 → 29
	if r.Coverage != 29 {
		t.Errorf("coverage with skips: got %d, want 29", r.Coverage)
	}
}

func TestCompute_AllSkipsIsHonest(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusSkip, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusSkip, compliancekit.SeverityCritical),
	}
	r := Compute(in)
	if r.Score != 100 {
		t.Errorf("all skips: Score=%d, want 100 (convention: nothing to evaluate)", r.Score)
	}
	if r.Coverage != 0 {
		t.Errorf("all skips: Coverage=%d, want 0 (nothing evaluable)", r.Coverage)
	}
}

func TestCompute_ErrorsCountWithFails(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusError, compliancekit.SeverityHigh),
	}
	r := Compute(in)
	if r.Score != 50 {
		t.Errorf("errors with fails: Score=%d, want 50 (1 pass / 1 error = 50)", r.Score)
	}
	if r.Errored != 20 || r.Failing != 0 {
		t.Errorf("errors with fails: got Errored=%d Failing=%d, want 20/0", r.Errored, r.Failing)
	}
}

// TestCompute_Deterministic confirms the score does not depend on map
// iteration order. Run Compute many times over the same shuffled
// input and assert every result is identical.
func TestCompute_Deterministic(t *testing.T) {
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityCritical),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusError, compliancekit.SeverityMedium),
		mkFinding(compliancekit.StatusSkip, compliancekit.SeverityLow),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityInfo),
	}
	first := Compute(in)
	for i := 0; i < 100; i++ {
		r := Compute(in)
		if r != first {
			t.Fatalf("nondeterministic: iter %d got %+v, first got %+v", i, r, first)
		}
	}
}

// TestCompute_Monotonic_PassUp confirms that converting a fail to a
// pass never decreases the score.
func TestCompute_Monotonic_PassUp(t *testing.T) {
	base := []compliancekit.Finding{
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
	}
	baseScore := Compute(base).Score

	// Convert one fail to pass.
	improved := make([]compliancekit.Finding, len(base))
	copy(improved, base)
	improved[0].Status = compliancekit.StatusPass
	improvedScore := Compute(improved).Score

	if improvedScore < baseScore {
		t.Errorf("monotonicity violated: base=%d improved=%d (pass-up should not decrease)", baseScore, improvedScore)
	}
}

// TestCompute_Monotonic_FailDown confirms that converting a pass to a
// fail never increases the score.
func TestCompute_Monotonic_FailDown(t *testing.T) {
	base := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityHigh),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityHigh),
	}
	baseScore := Compute(base).Score

	degraded := make([]compliancekit.Finding, len(base))
	copy(degraded, base)
	degraded[0].Status = compliancekit.StatusFail
	degradedScore := Compute(degraded).Score

	if degradedScore > baseScore {
		t.Errorf("monotonicity violated: base=%d degraded=%d (fail-down should not increase)", baseScore, degradedScore)
	}
}

// TestCompute_SeverityWeightsHonored verifies the (50/20/8/3/1) curve.
// A single critical pass should outweigh a low pass.
func TestCompute_SeverityWeightsHonored(t *testing.T) {
	// 1 critical pass (50) + 1 low fail (3) → 50/53 = 94
	in := []compliancekit.Finding{
		mkFinding(compliancekit.StatusPass, compliancekit.SeverityCritical),
		mkFinding(compliancekit.StatusFail, compliancekit.SeverityLow),
	}
	r := Compute(in)
	if r.Score != 94 {
		t.Errorf("weight curve: Score=%d, want 94 (50/53)", r.Score)
	}
}
