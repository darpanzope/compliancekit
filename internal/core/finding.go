package core

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// Finding is the atomic unit of compliancekit output: one statement
// about one resource from one check.
//
// Findings are produced by check evaluators, accumulated by the engine,
// and consumed by reporters. A scan with N resources and M checks may
// produce up to N*M findings, though most carry StatusPass and are
// dropped by the default min_report filter.
type Finding struct {
	// CheckID identifies the originating check; matches Check.ID exactly.
	CheckID string `json:"check_id"`

	// Status is the evaluation outcome (pass / fail / skip / error).
	Status Status `json:"status"`

	// Severity is denormalized from the originating Check so reporters
	// and CLI filters can act on it without joining against the catalogue.
	Severity Severity `json:"severity"`

	// Resource identifies the resource the finding is about. A scan
	// targeting account-level configuration may use a synthetic
	// account resource here.
	Resource ResourceRef `json:"resource"`

	// Message is a short human-readable description specific to this
	// finding, typically including the offending attribute value.
	// Example: `bucket "assets" has acl=public-read`.
	Message string `json:"message,omitempty"`

	// Evidence optionally points at captured raw data for the evidence pack.
	// Empty for findings derived from cross-resource logic with no single
	// underlying API response.
	Evidence EvidencePtr `json:"evidence,omitempty"`

	// Tags propagate filter labels from the check or resource. CLI flags
	// (--tags) match against this slice.
	Tags []string `json:"tags,omitempty"`

	// Timestamp is when the finding was produced (engine end-of-scan time).
	// All findings from a single scan share the same Timestamp.
	Timestamp time.Time `json:"timestamp"`
}

// Fingerprint returns a stable hex hash over the (check_id, resource.id,
// status) triple. The diff engine at v0.6+ uses this to correlate
// findings across scans and classify them as new / existing / resolved.
//
// Severity, Message, Tags, Evidence, and Timestamp are deliberately
// excluded: a finding whose wording changes between runs should still
// be recognized as the same finding.
func (f Finding) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", f.CheckID, f.Resource.ID, f.Status)
	return fmt.Sprintf("%x", h.Sum(nil))
}
