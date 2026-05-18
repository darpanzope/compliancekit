package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Finding and Source are v1.0 aliases of the public types. See
// severity.go for the migration rationale.
type (
	Finding = compliancekit.Finding
	Source  = compliancekit.Source
)
