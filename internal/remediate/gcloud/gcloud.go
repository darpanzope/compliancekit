// Package gcloud implements remediate.Strategy renderers for the
// FormatGCloud output. One-liner `gcloud <service> ...` commands
// for the same GCP CheckIDs covered by internal/remediate/terraform/
// gcp.go. Operators get format parity — choose Terraform when the
// resource is in HCL, choose gcloud for live-cloud-only fixes.
//
// Convention mirrors awscli's: VerifyCmd populated for every fix;
// RollbackCmd populated when the inverse is a single command;
// RiskManual sentinels for cases that need permission-audit or
// multi-step coordinated cutover.
package gcloud

import (
	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatGCloud} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatGCloud {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}
