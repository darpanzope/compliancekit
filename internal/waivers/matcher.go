package waivers

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Match scans the active waivers and returns the first one matching
// the (CheckID, ResourceID) pair. Returns nil if no active waiver
// applies.
//
// Match semantics at v0.18:
//
//   - CheckID: glob-style match via path.Match. Supports `*`
//     (match-any-segment) and `?` (single-char) wildcards. Literal
//     IDs are the common case; wildcards exist for waiving a whole
//     check family (e.g. `aws-s3-*`) when narrow waivers prove
//     repetitive in practice.
//   - ResourceID: glob-style match. Wildcards across the path
//     separator (`/`) are supported because resource IDs use `.`
//     not `/`. Operators waiving "every droplet" use `digitalocean.
//     droplet.*`.
//   - First-match-wins. Active waivers are iterated in (CheckID,
//     ResourceID) sort order (set at NewWaiverList time) so the
//     match is deterministic across runs.
//
// Match does NOT consider Expires — the active vs expired
// classification happens at load time inside NewWaiverList. Callers
// that need expiry-aware behavior at Match time should re-load
// the list with a fresh `now`.
func (l *WaiverList) Match(checkID, resourceID string) *Waiver {
	if l == nil {
		return nil
	}
	for i := range l.Active {
		w := &l.Active[i]
		if matchID(w.CheckID, checkID) && matchID(w.ResourceID, resourceID) {
			return w
		}
	}
	return nil
}

// matchID returns true iff pattern matches target. Literal pattern =
// exact equality (the common case, fast path). Pattern containing
// glob metacharacters runs filepath.Match. Malformed patterns fall
// back to literal equality — a user-written pattern like "[" still
// matches a target literally containing "[" rather than failing
// silently. filepath.Match's ErrBadPattern is the only error path.
func matchID(pattern, target string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == target
	}
	ok, err := filepath.Match(pattern, target)
	if err != nil {
		return pattern == target
	}
	return ok
}

// Apply mutates a Findings slice in place: each finding whose
// (CheckID, Resource.ID) matches an active waiver gets its Status
// flipped to StatusSkip + Waiver populated with the WaiverRef.
//
// Returns the count of findings that were muted, for the engine /
// CLI summary line ("N findings muted by waivers").
//
// Apply also synthesizes one info-level Finding per expired waiver
// so the auditor sees lapses as explicit findings (CheckID =
// "compliancekit-waiver-expired"). The synthesized findings carry
// a WaiverRef too so reporters can render the original reason +
// approver + lapsed-by-N-days detail.
//
// `now` is injected (not time.Now) so tests pin a deterministic
// clock; the production caller (scan engine) passes time.Now().UTC().
func (l *WaiverList) Apply(findings []core.Finding, now time.Time) (muted int, synthesized []core.Finding) {
	if l == nil {
		return 0, nil
	}
	for i := range findings {
		f := &findings[i]
		// Only actionable findings can be muted. A passing finding
		// is already non-actionable; muting it would be a status
		// downgrade rather than an upgrade.
		if !f.Status.IsActionable() {
			continue
		}
		w := l.Match(f.CheckID, f.Resource.ID)
		if w == nil {
			continue
		}
		f.Status = core.StatusSkip
		f.Waiver = w.ToRef()
		// Append the audit-trail tag so cross-tool consumers can
		// filter on `waived` without parsing the Waiver block.
		if !hasTag(f.Tags, "waived") {
			f.Tags = append(f.Tags, "waived")
		}
		muted++
	}
	synthesized = synthesizeExpiredFindings(l.Expired, now)
	return muted, synthesized
}

// synthesizeExpiredFindings emits one info-level Finding per expired
// waiver so auditors see the lapse as an explicit, ranked finding
// rather than as a silently-revived prior finding. CheckID is
// `compliancekit-waiver-expired`; the Waiver block carries the
// original metadata so reporters can render "lapsed N days ago".
func synthesizeExpiredFindings(expired []Waiver, now time.Time) []core.Finding {
	if len(expired) == 0 {
		return nil
	}
	out := make([]core.Finding, 0, len(expired))
	// Stable order for deterministic evidence-pack diffs.
	sorted := make([]Waiver, len(expired))
	copy(sorted, expired)
	sort.SliceStable(sorted, func(i, j int) bool {
		return less(sorted[i], sorted[j])
	})
	for _, w := range sorted {
		w := w
		ref := w.ToRef()
		days := -ref.DaysUntilExpiry(now) // positive = N days expired
		out = append(out, core.Finding{
			CheckID:  "compliancekit-waiver-expired",
			Status:   core.StatusFail,
			Severity: core.SeverityInfo,
			Resource: core.ResourceRef{
				ID:   w.ResourceID,
				Type: "compliancekit.waiver",
				Name: w.CheckID + "/" + w.ResourceID,
			},
			Message:   formatExpiryMessage(w, days),
			Tags:      []string{"waiver", "expired"},
			Waiver:    ref,
			Timestamp: now,
		})
	}
	return out
}

// formatExpiryMessage renders the operator-facing line. Keeps the
// CheckID + ResourceID + approver + days-expired together so log
// scrapers don't need to join multiple records.
func formatExpiryMessage(w Waiver, daysAgo int) string {
	if daysAgo < 0 {
		daysAgo = 0
	}
	return fmt.Sprintf("waiver for %s on %s (approver %s) expired %d days ago",
		w.CheckID, w.ResourceID, w.Approver, daysAgo)
}

// hasTag is a small string-membership helper. Avoids slices.Contains
// (Go 1.21+) so the package stays in the lowest-Go-version we support
// in CI; cheap to inline.
func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
