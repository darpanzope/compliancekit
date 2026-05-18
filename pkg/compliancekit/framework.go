package compliancekit

// CategoryCompliance / CategoryThreatModel classify a framework. Most
// frameworks are audit-shaped: a finite control catalog that a check
// either reaches or does not. MITRE ATT&CK is different — it maps to
// tactics + techniques along the kill chain, so the reporter renders
// it as a matrix view rather than a control checklist. Frameworks
// default to compliance when Category is empty.
const (
	CategoryCompliance  = "compliance"
	CategoryThreatModel = "threat_model"
)

// Framework is a compliance standard with a named set of controls.
//
// The wire shape (YAML/JSON tags) is the v1.0 contract — frameworks
// loaded from third-party YAMLs or assembled in code by embedders
// must serialize compatibly. The bundled catalog loader lives in
// internal/frameworks and is not part of the public API; embedders
// who want their own catalog instantiate Framework values directly.
type Framework struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
	URL         string `yaml:"url,omitempty"`
	// Category distinguishes audit-shaped compliance frameworks
	// (default) from threat-model frameworks like MITRE ATT&CK.
	// Empty == compliance for back-compat with v0.3-era yamls.
	Category string `yaml:"category,omitempty"`
	// Source cites the authoritative document the catalog was
	// derived from, for auditor transparency.
	Source string `yaml:"source,omitempty"`
	// Tactics is populated only for threat-model frameworks
	// (Category=threat_model). Ordered along the kill chain.
	Tactics  []Tactic           `yaml:"tactics,omitempty"`
	Controls map[string]Control `yaml:"controls"`
}

// IsThreatModel reports whether this framework renders as an ATT&CK-
// style matrix rather than a control checklist.
func (f *Framework) IsThreatModel() bool {
	return f.Category == CategoryThreatModel
}

// Tactic is a phase in a threat-model kill chain (MITRE ATT&CK uses
// "Initial Access", "Execution", ..., "Impact"). Each tactic has an
// ID like TA0001 and references the techniques mapped to it. Tactics
// are ignored for compliance-category frameworks.
type Tactic struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Techniques  []string `yaml:"techniques,omitempty"`
}

// Control is a single named requirement within a framework. The ID is
// the map key from YAML; bundle loaders backfill it into the struct so
// callers iterating Controls don't have to track the key separately.
//
// Optional fields support framework-specific metadata that the
// reporter surfaces conditionally:
//   - Family (NIST 800-53): "AC" for Access Control, "AU" for Audit, etc.
//   - Tags (CIS v8): "ig1"/"ig2"/"ig3" Implementation Group; (HIPAA):
//     "required" / "addressable" implementation specification class;
//     (ATT&CK technique): tactic ID(s) the technique belongs to.
//   - References: pointer back to authoritative paragraph numbers.
type Control struct {
	ID          string   `yaml:"-"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Family      string   `yaml:"family,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	References  []string `yaml:"references,omitempty"`
}

// HasTag reports whether the control carries the given tag. Case-
// insensitive to keep yaml editing friction low ("IG1" vs "ig1").
func (c Control) HasTag(tag string) bool {
	for _, t := range c.Tags {
		if equalFoldASCII(t, tag) {
			return true
		}
	}
	return false
}

// equalFoldASCII avoids pulling strings.EqualFold up to the package
// level just for one use site. Tag values are ASCII by convention
// (framework YAMLs are author-controlled), so the simple case-fold
// is correct.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// ResolvedControl pairs a Control with the Framework it belongs to,
// useful when iterating across the controls a single Check references.
type ResolvedControl struct {
	Framework *Framework
	Control   Control
}
