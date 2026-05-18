package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Status is the v1.0 alias of the public type. See severity.go for
// the migration rationale.
type Status = compliancekit.Status

const (
	StatusPass  = compliancekit.StatusPass
	StatusFail  = compliancekit.StatusFail
	StatusSkip  = compliancekit.StatusSkip
	StatusError = compliancekit.StatusError
)

// ParseStatus re-exports the public helper as a var so the
// underlying identifier is shared with the canonical package
// instead of wrapped.
var ParseStatus = compliancekit.ParseStatus
