package frameworks

import (
	"fmt"
	"strings"
)

// TailoringRule records that an operator has consciously scoped a
// specific control out of their audit. v0.12 introduces tailoring so
// honest mappings stay honest — an inventory check that maps to PCI-
// DSS 10.6.1 still ships that mapping, and the operator declares
// "out of scope, no PAN data here" via a tailoring rule. The evidence
// pack carries the justification alongside the finding so auditors
// see the omission with its reason.
type TailoringRule struct {
	// Framework is the framework ID the rule applies to (e.g. "soc2",
	// "pci-dss-v4"). Matched case-sensitively against framework.ID.
	Framework string `mapstructure:"framework" yaml:"framework"`
	// Control is the control ID within the framework (e.g. "CC1.4",
	// "10.6.1"). Matched against the control map key.
	Control string `mapstructure:"control" yaml:"control"`
	// Justification is the operator's written reason for scoping the
	// control out. v0.12 requires a non-empty justification — an
	// auditor who reads the evidence pack should understand the
	// decision without back-channeling the operator.
	Justification string `mapstructure:"justification" yaml:"justification"`
}

// Tailoring is the loaded set of operator-declared scope-outs. v0.12
// surfaces it through the evidence pack (tailoring.json + a column
// in control-mapping.csv) and the HTML reporter (visible "scoped out"
// chip on the control).
type Tailoring struct {
	Rules []TailoringRule
}

// NewTailoring builds a Tailoring from a config rule list, validating
// non-empty fields. Cross-validation against the loaded framework
// catalog (does the framework exist? does the control exist within
// it?) happens lazily via Validate so callers can construct a
// Tailoring before LoadAll has run.
func NewTailoring(rules []TailoringRule) (*Tailoring, error) {
	out := &Tailoring{Rules: make([]TailoringRule, 0, len(rules))}
	for i, r := range rules {
		if strings.TrimSpace(r.Framework) == "" {
			return nil, fmt.Errorf("tailoring rule %d: framework is required", i)
		}
		if strings.TrimSpace(r.Control) == "" {
			return nil, fmt.Errorf("tailoring rule %d: control is required", i)
		}
		if strings.TrimSpace(r.Justification) == "" {
			return nil, fmt.Errorf("tailoring rule %d (%s / %s): justification is required",
				i, r.Framework, r.Control)
		}
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}

// Lookup returns the justification an operator gave for scoping out a
// (framework, control) pair, plus a flag for "is this control
// tailored out?". Empty justification + false means the control is
// in scope.
func (t *Tailoring) Lookup(framework, control string) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, r := range t.Rules {
		if r.Framework == framework && r.Control == control {
			return r.Justification, true
		}
	}
	return "", false
}

// IsTailored is the boolean variant of Lookup.
func (t *Tailoring) IsTailored(framework, control string) bool {
	_, yes := t.Lookup(framework, control)
	return yes
}

// Validate checks every rule against the loaded framework catalog
// and returns a slice of errors (one per unresolvable rule) so the
// CLI can surface them all at once rather than one-at-a-time.
func (t *Tailoring) Validate() []error {
	if t == nil || len(t.Rules) == 0 {
		return nil
	}
	all, err := All()
	if err != nil {
		return []error{fmt.Errorf("load frameworks: %w", err)}
	}
	var problems []error
	for i, r := range t.Rules {
		fw, ok := all[r.Framework]
		if !ok {
			problems = append(problems, fmt.Errorf("tailoring rule %d: unknown framework %q", i, r.Framework))
			continue
		}
		if _, ok := fw.Controls[r.Control]; !ok {
			problems = append(problems, fmt.Errorf("tailoring rule %d: framework %q has no control %q", i, r.Framework, r.Control))
		}
	}
	return problems
}

// Count returns the number of rules. Convenience for evidence-pack
// header text ("3 controls tailored out").
func (t *Tailoring) Count() int {
	if t == nil {
		return 0
	}
	return len(t.Rules)
}
