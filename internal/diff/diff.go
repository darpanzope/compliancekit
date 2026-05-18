// Package diff classifies a current scan's findings against a
// previously captured baseline. Three buckets:
//
//   - new      — fingerprint not in baseline
//   - existing — fingerprint present in both, status unchanged
//   - resolved — fingerprint in baseline, not in current scan
//
// A fourth implicit case ("fingerprint present in both, status
// changed") is folded into `new` -- the status is the load-bearing
// piece of the fingerprint at v0.6, so a status change manifests as
// a different fingerprint already. Future v0.x may surface
// "regressed" / "improved" as their own buckets if the use case
// demands.
//
// The package is intentionally output-format-agnostic. The CLI layer
// renders the DiffResult into the human-readable format an operator
// expects; downstream tools (a future Slack notifier, a CI dashboard)
// will read the same struct.
package diff

import (
	"github.com/darpanzope/compliancekit/internal/baseline"
	"github.com/darpanzope/compliancekit/internal/score"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// DiffResult is the typed shape downstream tooling joins against.
// Counts are pre-computed because every consumer needs them; the
// raw slices are kept so a renderer can drill in.
type DiffResult struct {
	New      []compliancekit.Finding // findings whose fingerprint is not in the baseline
	Existing []compliancekit.Finding // findings whose fingerprint matches the baseline
	Resolved []baseline.Entry        // baseline entries whose fingerprint is no longer in the scan

	// PreviousScore + CurrentScore come from the baseline (captured
	// at baseline time) and a fresh Compute() over the current
	// findings, respectively.
	PreviousScore int
	CurrentScore  int
}

// Compute joins current findings against the baseline. Findings
// arriving in `current` are de-duplicated by fingerprint -- a
// finding referenced under multiple framework controls counts once
// in the diff, matching the baseline's own dedup.
func Compute(b baseline.Baseline, current []compliancekit.Finding) DiffResult {
	baselineSet := b.FingerprintSet()

	currentSet := map[string]compliancekit.Finding{}
	for _, f := range current {
		fp := f.Fingerprint()
		if _, dup := currentSet[fp]; dup {
			continue
		}
		currentSet[fp] = f
	}

	var (
		newFindings []compliancekit.Finding
		existing    []compliancekit.Finding
		resolved    []baseline.Entry
	)
	for fp, f := range currentSet {
		if _, inBaseline := baselineSet[fp]; inBaseline {
			existing = append(existing, f)
		} else {
			newFindings = append(newFindings, f)
		}
	}
	for fp, entry := range baselineSet {
		if _, stillPresent := currentSet[fp]; !stillPresent {
			resolved = append(resolved, entry)
		}
	}

	// Sort each slice by fingerprint so the output is byte-stable
	// across runs over identical input. The CLI layer can re-sort
	// for display (e.g. by severity desc); the package guarantee is
	// that this raw slice is deterministic.
	sortFindings(newFindings)
	sortFindings(existing)
	sortEntries(resolved)

	dedupedCurrent := make([]compliancekit.Finding, 0, len(currentSet))
	for _, f := range currentSet {
		dedupedCurrent = append(dedupedCurrent, f)
	}

	return DiffResult{
		New:           newFindings,
		Existing:      existing,
		Resolved:      resolved,
		PreviousScore: b.Score,
		CurrentScore:  score.Compute(dedupedCurrent).Score,
	}
}

// CountsBySeverity tallies a slice of findings into a per-severity
// map keyed by the lowercase severity name. Used by the CLI
// renderer to produce the "+ 2 new (1 high, 1 medium)" footer line.
func CountsBySeverity(findings []compliancekit.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	return counts
}

// CountsBySeverityEntries is the entries-flavored version of
// CountsBySeverity, for Resolved which holds Entry rather than Finding.
func CountsBySeverityEntries(entries []baseline.Entry) map[string]int {
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Severity.String()]++
	}
	return counts
}

// HasNewAtOrAbove reports whether any New finding is actionable
// (fail/error) and at or above the given severity. Powers the
// `--fail-on=new-<sev>` exit-code gate.
func (r DiffResult) HasNewAtOrAbove(level compliancekit.Severity) bool {
	for _, f := range r.New {
		if f.Status.IsActionable() && f.Severity >= level {
			return true
		}
	}
	return false
}

// HasActionableAtOrAbove reports whether ANY current finding (new
// or existing) is actionable at or above the given severity. Powers
// the `--fail-on=<sev>` gate, identical in shape to the scan
// command's gate.
func (r DiffResult) HasActionableAtOrAbove(level compliancekit.Severity) bool {
	for _, f := range r.New {
		if f.Status.IsActionable() && f.Severity >= level {
			return true
		}
	}
	for _, f := range r.Existing {
		if f.Status.IsActionable() && f.Severity >= level {
			return true
		}
	}
	return false
}

func sortFindings(in []compliancekit.Finding) {
	// Use insertion sort -- the slices are small (tens or low
	// hundreds of findings in any practical CI scenario) and the
	// stdlib sort import adds zero functional value for this size.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1].Fingerprint() > in[j].Fingerprint(); j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}

func sortEntries(in []baseline.Entry) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1].Fingerprint > in[j].Fingerprint; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}
