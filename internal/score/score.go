// Package score computes the 0-100 hardening score the v0.6 milestone
// adds as the headline metric.
//
// Inputs: a slice of core.Finding.
// Outputs: a deterministic, monotonic Result with the score, the
// coverage fraction, and the per-status weighted counts.
//
// Formula (locked at v0.6 per DECISIONS.md ADR-008):
//
//	weights = { critical: 50, high: 20, medium: 8, low: 3, info: 1 }
//
//	evaluable_findings  = [f for f in findings if f.status != skip]
//	total_weight        = sum(weight[f.severity] for f in evaluable_findings)
//	passing_weight      = sum(weight[f.severity] for f in evaluable_findings if f.status == pass)
//
//	if total_weight == 0: score = 100
//	else:                 score = round(100 * passing_weight / total_weight)
//
// Skips are excluded from both numerator and denominator -- they
// reflect "we couldn't evaluate this," not pass or fail. Errors are
// counted with fails. Pass is the only positive contributor.
//
// The score is deterministic (same inputs -> same output, no map
// iteration ordering, no wall-clock dependency) and monotonic
// (converting a fail to a pass cannot decrease the score; the reverse
// cannot increase it). Both properties are pinned by tests.
package score

import (
	"github.com/darpanzope/compliancekit/internal/core"
)

// severityWeight maps a severity tier to its contribution to the score
// denominator. The curve (50 / 20 / 8 / 3 / 1) is non-linear on
// purpose: a single critical finding dominates several low ones,
// matching how operators triage. Fixed at v0.6; configurability is
// rejected by ADR-008 so cross-fleet comparisons stay meaningful.
var severityWeight = map[core.Severity]int{
	core.SeverityCritical: 50,
	core.SeverityHigh:     20,
	core.SeverityMedium:   8,
	core.SeverityLow:      3,
	core.SeverityInfo:     1,
}

// Result is the score package's contract. It carries the headline
// integer plus the per-status weighted counts so a caller (the CLI
// footer, the HTML reporter, the evidence pack index) can render a
// breakdown without re-doing the math.
//
// All weight fields are integers in the same weight-unit space as
// severityWeight, not raw finding counts. Total = Passing + Failing +
// Errored (skipped is the parallel Skipped field, deliberately
// excluded from Total).
type Result struct {
	// Score is the headline 0-100 integer. 100 means everything we
	// could evaluate passed. 0 means everything we could evaluate
	// failed. Excludes skips entirely.
	Score int

	// Coverage is the percentage of finding weight that was
	// evaluable (not skipped). 0-100. A score of 100 with a
	// coverage of 10 is misleading without context; render both.
	Coverage int

	// Total is the sum of severity weights of evaluable findings
	// (everything except skips).
	Total int

	// Passing is the sum of severity weights of findings with
	// status pass.
	Passing int

	// Failing is the sum of severity weights of findings with
	// status fail.
	Failing int

	// Errored is the sum of severity weights of findings with
	// status error. Counted in Total alongside Failing.
	Errored int

	// Skipped is the sum of severity weights of findings with
	// status skip. NOT included in Total; reported separately
	// for the coverage calculation and operator visibility.
	Skipped int
}

// Compute returns the Result for the given findings. Safe to call
// with a nil or empty slice -- returns Score=100, Coverage=100,
// everything else zero (the "nothing to evaluate, no problems" state).
func Compute(findings []core.Finding) Result {
	var r Result
	for _, f := range findings {
		w := severityWeight[f.Severity]
		switch f.Status {
		case core.StatusPass:
			r.Passing += w
			r.Total += w
		case core.StatusFail:
			r.Failing += w
			r.Total += w
		case core.StatusError:
			r.Errored += w
			r.Total += w
		case core.StatusSkip:
			r.Skipped += w
		}
	}

	if r.Total == 0 {
		// Either no findings at all, or every finding was a skip.
		// "Nothing to evaluate" is conventionally a perfect score
		// rather than zero -- a zero would falsely punish an
		// empty scan. The Coverage field tells the caller whether
		// to trust the 100.
		r.Score = 100
	} else {
		// Round-half-up at the integer boundary so the score is
		// deterministic across architectures (Go's math.Round is
		// round-half-away-from-zero which is equivalent on
		// non-negative inputs, but we do the arithmetic in pure
		// integers to be safe).
		r.Score = (100*r.Passing + r.Total/2) / r.Total
	}

	total := r.Total + r.Skipped
	if total == 0 {
		r.Coverage = 100
	} else {
		r.Coverage = (100*r.Total + total/2) / total
	}

	return r
}
