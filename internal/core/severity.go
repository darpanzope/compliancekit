// Package core defines the value types and interfaces shared across the
// compliancekit codebase: Severity, Status, Resource, ResourceGraph,
// Finding, Check, Collector, Evaluator, and the check registry.
//
// Every other internal package depends on core; core depends only on
// the standard library.
package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity classifies the impact of a finding.
//
// Ordering is meaningful: a Severity value compares correctly with the
// usual relational operators. The CLI severity filter (--fail-on=high)
// relies on this ordering, so adding a new level requires preserving
// the ascending-impact order.
type Severity int

const (
	// SeverityUnknown is the zero value. It signals "not set yet" rather
	// than a real severity; checks must populate a real level.
	SeverityUnknown Severity = iota

	SeverityInfo     // observation, no action required
	SeverityLow      // hygiene, recommended setting
	SeverityMedium   // best-practice gap, hardening miss
	SeverityHigh     // meaningful exposure, audit-failing
	SeverityCritical // exploitable now, data at immediate risk
)

// String returns the lowercase canonical name used in YAML and CLI flags.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity is the inverse of String. It is case-insensitive and
// tolerates surrounding whitespace, so values from CLI flags or YAML
// parse without preprocessing.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("unknown severity %q", s)
	}
}

// MarshalJSON emits the canonical lowercase string. Findings are routinely
// serialized to JSON for CI consumption, so this matters for stability.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON accepts the canonical lowercase string and rejects unknown values.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	sev, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}
