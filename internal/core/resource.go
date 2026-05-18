package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// Resource, ResourceRef, and EvidencePtr are v1.0 aliases of the
// public types. See severity.go for the migration rationale.
type (
	Resource    = compliancekit.Resource
	ResourceRef = compliancekit.ResourceRef
	EvidencePtr = compliancekit.EvidencePtr
)
