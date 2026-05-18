// Package awscli implements remediate.Strategy renderers for the
// FormatAWSCLI output. Each strategy emits an `aws <service> ...`
// one-liner (or short multi-step script) that flips the bad-state
// finding to good-state via the AWS public API.
//
// Strategies pair with internal/remediate/terraform/aws.go: the
// same CheckIDs are covered in both packages so an operator picks
// the format that matches their workflow. Terraform is the right
// answer when the resource is managed in code; aws-cli is the right
// answer for live-cloud-only resources or for the immediate-fix
// step before code lands.
//
// Convention for the emitted Content:
//   - Single-line where possible. Long commands wrap with `\` so the
//     runbook stays readable.
//   - Every value the operator's shell would interpret runs through
//     render.ShellQuote — bucket names, ARNs, regions, and so on.
//   - VerifyCmd is always populated: same service, *describe-* or
//     *get-* variant, projecting just the single field the fix
//     touched. The operator can run verify immediately after apply.
//   - RollbackCmd is populated when the inverse command is trivially
//     expressible (set-acl private → set-acl public-read), empty when
//     it would require multi-step or destructive operations.
package awscli

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type strategyFunc func(compliancekit.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatAWSCLI} }
func (s *strategy) Render(f compliancekit.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatAWSCLI {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

// regionOf returns the AWS region from the finding's ResourceRef,
// falling back to "us-east-1" when not set. Most CLI commands need
// --region; this lets strategies stay terse.
func regionOf(f compliancekit.Finding) string {
	if f.Resource.Region != "" {
		return f.Resource.Region
	}
	return "us-east-1"
}
