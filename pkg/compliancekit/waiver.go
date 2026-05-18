package compliancekit

import "time"

// WaiverRef is the v0.18+ typed metadata block populated on
// core.Finding when a matching waiver muted the underlying check.
// Lives in core (not internal/waivers) so adding it to Finding does
// not create an import cycle — same pattern as Vulnerability + Secret.
//
// Auditor-visible by design: a waived finding is NOT hidden, it
// flows through every reporter (markdown, sarif, ocsf, html,
// evidence pack) as StatusSkip with this block populated so the
// auditor sees the waiver acknowledgement plus the reason +
// approver that justified it.
type WaiverRef struct {
	// CheckID is the catalog ID the waiver matched on. Always
	// non-empty; helps round-tripping when a reporter drops the
	// surrounding Finding.CheckID for some reason.
	CheckID string `json:"check_id"`

	// ResourceID is the resource the waiver matched. Always
	// non-empty; the matcher requires both CheckID + ResourceID
	// in v0.18 (broader scopes deferred — see ADR-013).
	ResourceID string `json:"resource_id"`

	// Reason is the operator-supplied justification. Required by
	// the loader; an empty Reason fails waiver validation. The
	// auditor reads this to understand WHY the deviation is
	// acceptable.
	Reason string `json:"reason"`

	// Approver is the human who signed off. Required by the loader.
	// Convention: email address or "@github-username"; the auditor
	// uses this to chase up if context is needed.
	Approver string `json:"approver"`

	// Expires is the date the waiver lapses. Expired waivers stop
	// muting and emit their own info-level finding ("waiver X
	// expired N days ago") so the auditor sees the lapse instead
	// of silent re-coverage. UTC date; loader parses YYYY-MM-DD.
	Expires time.Time `json:"expires"`

	// Source identifies where the waiver was declared. Three values
	// at v0.18: "file" (waivers.yaml entry), "annotation" (in-code
	// // compliancekit:waive ... comment), or "" (legacy / unknown).
	Source string `json:"source,omitempty"`

	// SourcePath optionally points at the file the waiver was
	// declared in. waivers.yaml path for Source=="file"; the
	// annotated source file for Source=="annotation".
	SourcePath string `json:"source_path,omitempty"`
}

// IsActive reports whether the waiver is still in effect at time t.
// A waiver with a zero-value Expires is treated as permanent
// (rejected by the loader — every waiver MUST have an expiry — but
// the helper exists for forward-compatibility).
func (w *WaiverRef) IsActive(t time.Time) bool {
	if w == nil {
		return false
	}
	if w.Expires.IsZero() {
		return true
	}
	return t.Before(w.Expires)
}

// DaysUntilExpiry returns the number of whole days between t and
// the waiver's Expires date. Negative when expired. Used by the
// expiry-warning pipeline to surface "expiring in 30 days" alerts.
func (w *WaiverRef) DaysUntilExpiry(t time.Time) int {
	if w == nil || w.Expires.IsZero() {
		return 0
	}
	return int(w.Expires.Sub(t).Hours() / 24)
}
