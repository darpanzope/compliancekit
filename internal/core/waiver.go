package core

import "github.com/darpanzope/compliancekit/pkg/compliancekit"

// WaiverRef is the v1.0 alias of the public typed-metadata block
// populated on a Finding when a matching waiver muted it. See
// severity.go for the migration rationale.
type WaiverRef = compliancekit.WaiverRef
