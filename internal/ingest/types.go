package ingest

import (
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Options carries per-call configuration into an Ingester.Ingest call.
// Every adapter respects every field that applies to it; fields not
// relevant to a particular wire format are silently ignored.
type Options struct {
	// Provenance is recorded onto every Finding the adapter emits.
	// At minimum the caller should set Provenance.Tool so downstream
	// consumers can distinguish Trivy findings from Checkov findings
	// even when both arrive via SARIF.
	Provenance Provenance

	// Mapping (optional) translates an external rule identifier
	// (e.g. Trivy's "CVE-2024-1234" or Checkov's "CKV_AWS_18") into
	// one or more compliancekit (framework, control) pairs. Nil
	// means the adapter does its best with built-in heuristics
	// (typically: tag-based mapping or none at all). See MappingTable.
	Mapping *MappingTable

	// Graph (optional) is the resource graph from a prior native
	// scan. Adapters use it for two reasons: (1) attach an ingested
	// finding to an existing resource when the external tool names
	// one we already know about, and (2) check before creating a
	// phantom resource so we don't duplicate. Nil means the adapter
	// freely creates phantoms for every distinct subject.
	Graph *compliancekit.ResourceGraph

	// DefaultSeverity is used when the external tool's severity
	// can't be parsed or is absent. Default compliancekit.SeverityMedium.
	DefaultSeverity compliancekit.Severity

	// FailOnUnmapped, when true, causes Ingest to error if any
	// finding has no mapping in MappingTable. Default false: an
	// unmapped finding is emitted with no framework attribution
	// and a warning is added to Result.Warnings.
	FailOnUnmapped bool
}

// Provenance metadata travels with every Finding the adapter produces.
// The CLI populates this from --tool, --tool-version, and the input
// file path; ingest config blocks populate it from the YAML.
type Provenance struct {
	// Tool is the canonical identifier of the producing tool, e.g.
	// "trivy", "checkov", "aws-security-hub". Lowercase, no spaces.
	// Used as a key for built-in mapping tables.
	Tool string

	// ToolVersion (optional) is the version string the tool itself
	// reports, e.g. "v0.50.2". Aids audit-trail reproducibility but
	// not relied on for correctness.
	ToolVersion string

	// Format is the wire format the bytes were decoded from. Set
	// by the adapter (matches Ingester.Format()); callers do not
	// need to populate it.
	Format string

	// File (optional) is the path of the source file. Surfaced in
	// evidence-pack manifests for traceability.
	File string

	// IngestedAt is when the ingest call ran. Set by the adapter
	// if zero on entry; callers may pre-populate for deterministic
	// tests.
	IngestedAt time.Time
}

// Result is what an Ingester returns. Findings are projected onto
// (resource, framework, control) tuples; Resources are phantom
// resources the adapter created when the external tool named a
// subject the existing graph did not contain. Warnings are
// non-fatal parse advisories (unrecognized rule IDs, missing
// severities mapped to default, etc.).
type Result struct {
	Findings  []compliancekit.Finding
	Resources []compliancekit.Resource
	Warnings  []string
}

// MappingTable translates an external tool's rule identifiers into
// compliancekit framework controls. One mapping entry per external
// rule ID; each entry may map to zero or more (framework, control)
// tuples. The yaml file is tailorable per operator-deployment.
//
// Built-in mapping tables ship under mappings/ in the repo and are
// loaded on-demand by Tool name. Operators can also point at their
// own mapping file via the ingest config block.
type MappingTable struct {
	// Tool identifies the producing tool the table covers, e.g.
	// "trivy", "checkov". One table per tool; mixing tools in a
	// single file is not supported (and not useful — different
	// tools use completely different rule-id conventions).
	Tool string `yaml:"tool"`

	// Version (optional) records which version of the producing
	// tool the table was authored against. Mismatch is non-fatal
	// but surfaces as a Result.Warning.
	Version string `yaml:"version,omitempty"`

	// Description (optional) is a one-line free-text note about
	// the mapping table.
	Description string `yaml:"description,omitempty"`

	// Rules maps an external rule identifier (Trivy's CVE-ID,
	// Checkov's CKV_AWS_*, KICS's query UUID, …) to its
	// compliancekit framework controls. Lookup is exact-string.
	Rules map[string]MappingRule `yaml:"rules"`
}

// MappingRule is one row in a MappingTable. Controls is the list of
// (framework, control) tuples to attribute the finding to.
type MappingRule struct {
	// Controls is the slice of framework controls this rule maps
	// to. A single rule frequently maps to multiple frameworks
	// (e.g. CIS + NIST 800-53 + ISO 27001), so this is a slice.
	Controls []ControlMapping `yaml:"controls"`

	// Severity (optional) overrides the external tool's severity.
	// Useful when the tool's severity scale doesn't match
	// compliancekit's, or when the operator wants to elevate
	// specific rule families regardless of how the tool ranks them.
	Severity string `yaml:"severity,omitempty"`

	// Tags (optional) propagate onto the Finding so existing CLI
	// filters (--tags) match ingested findings the same way they
	// match native ones.
	Tags []string `yaml:"tags,omitempty"`
}

// ControlMapping names one (framework, control) pair an external
// rule attributes to. Framework matches a framework id from
// internal/frameworks; Control matches a Control.ID inside that
// framework. The ingester checks both exist at scan time and
// surfaces a warning when either is missing.
type ControlMapping struct {
	Framework string `yaml:"framework"`
	Control   string `yaml:"control"`
}

// Lookup returns the mapping rule for ruleID, or (zero, false) if
// no entry is registered.
func (m *MappingTable) Lookup(ruleID string) (MappingRule, bool) {
	if m == nil {
		return MappingRule{}, false
	}
	r, ok := m.Rules[ruleID]
	return r, ok
}
