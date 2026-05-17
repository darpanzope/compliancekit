// Package waivers implements compliancekit's v0.18 muting layer:
// explicit, time-bounded, auditable acknowledgements that a specific
// (check, resource) pair is non-compliant by deliberate operator
// choice rather than oversight. Mirrors the v0.17 notify + v0.15
// remediate packages in shape: typed config, validating loader,
// engine integration via a single muting hook.
//
// What a waiver is NOT:
//
//   - It is not a baseline. Baselines record state; waivers record
//     decisions. ADR-013 (DECISIONS.md) spells the difference.
//   - It is not a check skip. A waived finding still RUNS through
//     the engine; the matcher swaps StatusFail → StatusSkip and
//     attaches a core.WaiverRef so the auditor sees both the
//     finding and the acknowledgement. Reports render the waiver
//     inline.
//   - It is not auto-renewing. Every waiver MUST have an explicit
//     Expires date; expired waivers stop muting and emit their own
//     info-level finding so the lapse is visible, not silent.
//
// Two declaration paths supported at v0.18:
//
//  1. waivers.yaml — central declarative file the loader walks.
//  2. // compliancekit:waive <check-id> <reason> — in-code
//     annotations in Terraform, Bash, YAML, Dockerfile, Python.
//     Lifted into the same WaiverList at scan time.
//
// Per ADR-013 both share one matcher + one apply hook so the
// reporter doesn't need a "where did this waiver come from"
// branch — the WaiverRef.Source field carries the provenance.
package waivers

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Waiver is the parsed entry from waivers.yaml (or from an in-code
// annotation lifted into the same shape). One Waiver matches one
// (CheckID, ResourceID) pair; broader scopes (per-framework,
// per-tag) are deferred per ADR-013.
//
// Validation rules (enforced by Load + Validate, not by the bare
// struct constructor):
//
//   - CheckID, ResourceID, Reason, Approver are all required.
//   - Expires must be in the future at the time of loading (the
//     loader emits info-level expired-waiver findings for past
//     dates, but the underlying Waiver is excluded from the
//     active matcher).
//   - Reason must be non-empty and non-trivial (≥ 16 chars). An
//     "OK" reason is rejected at load time so the audit trail
//     stays honest.
type Waiver struct {
	CheckID    string    `yaml:"check_id"    json:"check_id"`
	ResourceID string    `yaml:"resource_id" json:"resource_id"`
	Reason     string    `yaml:"reason"      json:"reason"`
	Approver   string    `yaml:"approver"    json:"approver"`
	Expires    time.Time `yaml:"expires"     json:"expires"`

	// Source is set by the loader. "file" for waivers.yaml entries
	// (the common case), "annotation" for in-code annotations
	// (Phase 6).
	Source string `yaml:"-" json:"source,omitempty"`

	// SourcePath is set by the loader. Path to waivers.yaml or to
	// the annotated source file. Populated for both "file" and
	// "annotation" sources.
	SourcePath string `yaml:"-" json:"source_path,omitempty"`
}

// minReasonLen is the lower bound enforced by Validate(). "16 chars"
// is what it takes to write a sentence rather than a sentence
// fragment. Catches "see ticket" without rejecting a real
// explanation. Tunable if it proves too aggressive in practice.
const minReasonLen = 16

// Validate confirms every field a Waiver requires is present + valid.
// Called by Load against each parsed entry; surface-exposed so the
// `compliancekit waivers validate` CLI subcommand can re-run the
// same checks against ad-hoc input.
func (w *Waiver) Validate() error {
	if w == nil {
		return errors.New("nil waiver")
	}
	if w.CheckID == "" {
		return errors.New("check_id is required")
	}
	if w.ResourceID == "" {
		return errors.New("resource_id is required")
	}
	if w.Reason == "" {
		return errors.New("reason is required")
	}
	if len(strings.TrimSpace(w.Reason)) < minReasonLen {
		return fmt.Errorf("reason must be at least %d non-whitespace characters (audit trail bar)", minReasonLen)
	}
	if w.Approver == "" {
		return errors.New("approver is required")
	}
	if w.Expires.IsZero() {
		return errors.New("expires is required (every waiver MUST be time-bounded — see ADR-013)")
	}
	return nil
}

// ToRef materializes the lightweight core.WaiverRef block attached
// to a muted Finding. Reporters consume the Ref; the Waiver itself
// stays inside the waivers package.
func (w *Waiver) ToRef() *core.WaiverRef {
	if w == nil {
		return nil
	}
	return &core.WaiverRef{
		CheckID:    w.CheckID,
		ResourceID: w.ResourceID,
		Reason:     w.Reason,
		Approver:   w.Approver,
		Expires:    w.Expires,
		Source:     w.Source,
		SourcePath: w.SourcePath,
	}
}

// WaiverList is the parsed + validated collection. Constructed via
// Load (or by an annotation scanner in Phase 6); never assembled
// directly by callers because the constructor's invariants matter
// — duplicate (CheckID, ResourceID) pairs are a load-time error
// not a runtime one.
type WaiverList struct {
	// Active contains waivers whose Expires > now at load time.
	Active []Waiver

	// Expired contains waivers whose Expires <= now. These do NOT
	// mute findings; they're held here so the engine can synthesize
	// info-level "waiver X expired" findings during evaluation
	// (Phase 5).
	Expired []Waiver
}

// NewWaiverList builds a WaiverList from a flat Waiver slice. The
// `now` parameter is injected (not derived from time.Now) so tests
// can pin a deterministic clock. Validates each entry; duplicates
// (same CheckID + ResourceID across two entries) are rejected
// because they hide which approver actually authorized.
//
// Returns the list + a slice of per-entry errors. Caller decides
// whether to fail the run on a non-empty error slice (the loader
// fails; the CLI's validate command surfaces and continues).
func NewWaiverList(entries []Waiver, now time.Time) (*WaiverList, []error) {
	list := &WaiverList{}
	seen := map[string]int{}
	var errs []error
	for i, w := range entries {
		w := w // copy for the slice append below
		if err := w.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("waiver #%d (%s/%s): %w", i+1, w.CheckID, w.ResourceID, err))
			continue
		}
		key := w.CheckID + "|" + w.ResourceID
		if first, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf("waiver #%d duplicates waiver #%d for (%s, %s)",
				i+1, first+1, w.CheckID, w.ResourceID))
			continue
		}
		seen[key] = i
		if w.Expires.After(now) {
			list.Active = append(list.Active, w)
		} else {
			list.Expired = append(list.Expired, w)
		}
	}
	// Stable sort by (CheckID, ResourceID) for deterministic
	// iteration in reports + the evidence pack.
	sort.SliceStable(list.Active, func(i, j int) bool {
		return less(list.Active[i], list.Active[j])
	})
	sort.SliceStable(list.Expired, func(i, j int) bool {
		return less(list.Expired[i], list.Expired[j])
	})
	return list, errs
}

func less(a, b Waiver) bool {
	if a.CheckID != b.CheckID {
		return a.CheckID < b.CheckID
	}
	return a.ResourceID < b.ResourceID
}

// Counts returns (active, expired, expiringSoon) for the doctor +
// scan summary lines. "expiring soon" = within the next 30 days.
func (l *WaiverList) Counts(now time.Time) (active, expired, expiringSoon int) {
	if l == nil {
		return 0, 0, 0
	}
	cutoff := now.AddDate(0, 0, 30)
	for _, w := range l.Active {
		if w.Expires.Before(cutoff) {
			expiringSoon++
		}
	}
	return len(l.Active), len(l.Expired), expiringSoon
}
