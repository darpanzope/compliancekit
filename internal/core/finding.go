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
	// and CLI filters can act on it without joining against the catalog.
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

	// Source records the provenance of this finding: native scan, or
	// ingested from an external tool (Trivy, AWS Security Hub, OSCAL
	// assessment results, …). nil for legacy findings written before
	// v0.13; reporters and the evidence pack treat absence as native
	// for backwards compatibility.
	//
	// v0.13+. Populated by either the engine (native) or an
	// internal/ingest adapter (external).
	Source *Source `json:"source,omitempty"`

	// Vulnerability is the v0.14+ typed metadata block populated when
	// the finding represents a CVE / GHSA / vendor advisory rather
	// than a posture issue. Trivy / Grype / Snyk / Dependabot ingest
	// adapters populate it; native checks leave it nil. Reporters
	// render CVE IDs natively when present.
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`

	// Secret is the v0.14+ typed metadata block populated when the
	// finding represents a leaked credential discovered by a secret
	// scanner (gitleaks, TruffleHog). Always carries a redacted
	// fingerprint, never the raw secret value — ADR-010 codifies
	// this hard rule.
	Secret *Secret `json:"secret,omitempty"`

	// Waiver is the v0.18+ typed metadata block populated when a
	// matching waiver muted this finding. Auditor-visible by
	// design: the Finding flows through every reporter as
	// StatusSkip with this block populated so the auditor sees
	// the acknowledgement + reason + approver. A nil Waiver means
	// the finding ran through the normal status machinery, NOT
	// that it was waived for an unrelated reason. See ADR-013.
	Waiver *WaiverRef `json:"waiver,omitempty"`
}

// Source describes where a Finding came from. Native findings produced
// by the scan engine set Type="native" and leave Tool/ToolVersion/Format
// empty. Findings produced by an internal/ingest adapter set Type="ingest"
// plus the tool identifier and the wire format that carried them in.
//
// Source travels with the finding through every reporter, the diff
// engine, and the evidence pack — operators and auditors can see
// "this control is flagged by both compliancekit's native check and
// Trivy v0.50.2" without losing either side of the trail.
type Source struct {
	// Type is "native" for engine-produced findings or "ingest" for
	// findings projected from an external tool's output.
	Type string `json:"type"`

	// Tool identifies the producer when Type=="ingest", e.g. "trivy",
	// "checkov", "aws-security-hub", "gcp-scc", "defender". Empty
	// when Type=="native".
	Tool string `json:"tool,omitempty"`

	// ToolVersion (optional) records the producing tool's version,
	// e.g. "v0.50.2". Useful for audit-trail reproducibility.
	ToolVersion string `json:"tool_version,omitempty"`

	// Format names the wire format the finding was decoded from
	// ("sarif", "ocsf", "oscal-ar"). Empty for native findings.
	Format string `json:"format,omitempty"`

	// File (optional) is the path of the source file the ingest
	// adapter read. Aids reproducibility but never relied on for
	// correctness — the finding is fully described without it.
	File string `json:"file,omitempty"`
}

// IsNative reports whether the finding was produced by the scan engine
// rather than ingested from an external tool. A nil Source counts as
// native (pre-v0.13 findings).
func (f Finding) IsNative() bool {
	return f.Source == nil || f.Source.Type == "native" || f.Source.Type == ""
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
