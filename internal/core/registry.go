package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Registry is the v1.0 alias of the public registry. See severity.go
// for the migration rationale.
type Registry = compliancekit.Registry

// Var-aliasing exposes the same underlying identifier as the public
// package — `core.Register` and `compliancekit.Register` are the same
// function, not a wrapper, so test code that swaps out the registry
// behaves identically across both call sites.
var (
	NewRegistry      = compliancekit.NewRegistry
	DefaultRegistry  = compliancekit.DefaultRegistry
	Register         = compliancekit.Register
	Unregister       = compliancekit.Unregister
	Lookup           = compliancekit.Lookup
	LookupCheck      = compliancekit.LookupCheck
	RegisteredChecks = compliancekit.RegisteredChecks
	RegisteredIDs    = compliancekit.RegisteredIDs
	RegisteredCount  = compliancekit.RegisteredCount
)
