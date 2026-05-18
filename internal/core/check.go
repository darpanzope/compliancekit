package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Check and CheckFunc are v1.0 aliases of the public types. See
// severity.go for the migration rationale.
type (
	Check     = compliancekit.Check
	CheckFunc = compliancekit.CheckFunc
)
