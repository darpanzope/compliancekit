package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Severity is the v1.0 alias of the public type. New code should
// prefer importing pkg/compliancekit directly; this alias keeps the
// internal/ codebase compiling during the v1.0 phase migration and
// will be removed in Phase 10 once every importer is updated.
type Severity = compliancekit.Severity

// Severity constants re-exported from the public package. Aliasing
// preserves typed-constant identity, so `core.SeverityCritical` and
// `compliancekit.SeverityCritical` compare equal and may be used
// interchangeably while the migration is in flight.
const (
	SeverityUnknown  = compliancekit.SeverityUnknown
	SeverityInfo     = compliancekit.SeverityInfo
	SeverityLow      = compliancekit.SeverityLow
	SeverityMedium   = compliancekit.SeverityMedium
	SeverityHigh     = compliancekit.SeverityHigh
	SeverityCritical = compliancekit.SeverityCritical
)

// ParseSeverity re-exports the public helper. Var (not func) so the
// underlying identifier is shared rather than wrapped — saves a stack
// frame on every parse and keeps the signature literally the same.
var ParseSeverity = compliancekit.ParseSeverity
