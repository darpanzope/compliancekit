package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// ResourceGraph is the v1.0 alias of the public type. See severity.go
// for the migration rationale.
type ResourceGraph = compliancekit.ResourceGraph

// NewResourceGraph re-exports the constructor. Var (not func) so the
// underlying identifier is shared with the canonical package.
var NewResourceGraph = compliancekit.NewResourceGraph
