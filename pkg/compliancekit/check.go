package compliancekit

import "context"

// Check is the parsed metadata of a single check from the YAML catalog.
//
// At runtime, a Check is paired with a CheckFunc registered in the
// check registry; together they form a complete check ready to run.
// The YAML lives at internal/checks/<provider>/*.yaml; the schema is
// documented in CHECKS.md.
type Check struct {
	// ID is the stable identifier, kebab-case. Convention:
	// "<provider>-<service>-<concise-rule>", e.g. "do-spaces-public-acl".
	// Never rename an ID; deprecate via the Deprecated field instead.
	ID string `yaml:"id" json:"id"`

	// Title is the short human-readable summary shown in reports.
	Title string `yaml:"title" json:"title"`

	// Severity is the impact classification. See severity.go.
	Severity Severity `yaml:"severity" json:"severity"`

	// Provider names the provider this check targets, e.g. "digitalocean".
	Provider string `yaml:"provider" json:"provider"`

	// Service narrows the provider area, e.g. "spaces", "droplets".
	Service string `yaml:"service,omitempty" json:"service,omitempty"`

	// ResourceType identifies the resource kind the check examines.
	ResourceType string `yaml:"resource_type,omitempty" json:"resource_type,omitempty"`

	// Description explains the check in prose. Shown in `checks show` and
	// the HTML report.
	Description string `yaml:"description" json:"description"`

	// Rationale optionally captures the "why this is bad" -- typically
	// citing an incident or threat model.
	Rationale string `yaml:"rationale,omitempty" json:"rationale,omitempty"`

	// Remediation is the human-readable fix. Specific commands beat
	// generic advice; CHECKS.md spells this out.
	Remediation string `yaml:"remediation" json:"remediation"`

	// Frameworks maps framework ID to the control IDs it satisfies,
	// e.g. {"soc2": ["CC6.1", "CC6.6"], "cis-v8": ["3.3"]}.
	Frameworks map[string][]string `yaml:"frameworks" json:"frameworks"`

	// Tags are filter labels propagated to Findings.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// References link to authoritative external sources (docs, CWEs, etc.).
	References []string `yaml:"references,omitempty" json:"references,omitempty"`

	// Scanner names the Go CheckFunc registered in the registry under
	// this ID. Mutually exclusive with Policy.
	Scanner string `yaml:"scanner,omitempty" json:"scanner,omitempty"`

	// Policy points at a Rego file. Available from v0.13 once the Rego
	// evaluator lands. Mutually exclusive with Scanner.
	Policy string `yaml:"policy,omitempty" json:"policy,omitempty"`

	// Deprecated marks the check as scheduled for removal.
	Deprecated bool `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`

	// DeprecatedIn records the version in which deprecation was announced,
	// e.g. "v0.7".
	DeprecatedIn string `yaml:"deprecated_in,omitempty" json:"deprecated_in,omitempty"`

	// ReplacedBy is the ID of the check that supersedes this one.
	ReplacedBy string `yaml:"replaced_by,omitempty" json:"replaced_by,omitempty"`
}

// CheckFunc is the signature every check evaluator must satisfy.
//
// Implementers read from the ResourceGraph and emit Findings. They MUST
// NOT perform I/O -- collectors do all data fetching; scanners only
// evaluate. The returned error signals "the check could not run" (data
// missing, ambiguous), not "the resource is non-compliant" (which is a
// Finding with StatusFail).
//
// At v0.1 implementers are plain Go functions registered via Register.
// At v0.13 Rego policies will be wrapped into CheckFuncs by the Rego
// evaluator; the signature was chosen so this addition requires no
// change to existing checks (see DECISIONS.md ADR-002).
type CheckFunc func(ctx context.Context, graph *ResourceGraph) ([]Finding, error)
