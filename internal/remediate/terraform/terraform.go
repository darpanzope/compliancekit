// Package terraform implements remediate.Strategy renderers for the
// FormatTerraform output. Strategies emit surgical-fix HCL blocks the
// operator drops into an existing TF root module — not full module
// rewrites and not `import` boilerplate. Operators who already manage
// the offending resource in Terraform paste the snippet alongside the
// existing definition; operators who don't can use the AWS-CLI /
// gcloud / az-cli / doctl / hcloud strategies registered by the
// sibling packages.
//
// Each provider gets one file (aws.go, gcp.go, do.go, hetzner.go,
// k8s.go); each file contains one strategy registration per CheckID.
// Strategies wrap a single render function with a fixed Format slice
// (always FormatTerraform here) and a declared RiskClass.
//
// CheckID coverage at v0.15:
//
//   - AWS: S3 (5), IAM (1 password-policy), CloudTrail (3), EC2 (2),
//     RDS (4), KMS (1), GuardDuty + Config (2)
//   - GCP: Storage (4), SQL (3), Compute (1), BigQuery (1), KMS (1)
//   - DigitalOcean: Spaces, Databases (subset)
//   - Hetzner: firewalls, servers (subset)
//   - Kubernetes (via Terraform's kubernetes provider): security
//     context, NetworkPolicy (subset; kubectl is the primary path)
//
// Strategies that cannot be expressed as a Terraform fix (credential
// rotation, key revocation, IAM user deletion) live in the
// internal/remediate/awscli / gcloud / azcli sibling packages, with
// a RiskManual sentinel snippet here so the runbook still surfaces
// the finding via the Terraform pipeline.
package terraform

import (
	"strings"
	"unicode"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// strategyFunc is the common shape of every renderer in this package.
// Returning an error is reserved for "I cannot render this even
// though I claimed the CheckID" — operators see this only when a
// strategy is buggy. The standard non-fix outcome is to return a
// Snippet with Risk=RiskManual and Notes explaining why.
type strategyFunc func(core.Finding) (remediate.Snippet, error)

// strategy is the shared adapter used by every register() call below.
// It pins Format to FormatTerraform; strategies that need to emit
// other formats register separately in the matching sibling package.
type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatTerraform} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatTerraform {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

// register is the tiny indirection every strategy file calls from
// init(). Keeps the per-file boilerplate to one line per CheckID.
func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

// tfIdent sanitizes s into a Terraform identifier (alphanumeric +
// underscore, can't start with a digit). Resource names like
// "my-bucket.production" become "my_bucket_production"; numeric
// prefixes are guarded with an underscore.
func tfIdent(s string) string {
	if s == "" {
		return "fix"
	}
	var sb strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			sb.WriteRune(unicode.ToLower(r))
		default:
			sb.WriteByte('_')
		}
	}
	out := sb.String()
	out = strings.Trim(out, "_")
	if out == "" {
		return "fix"
	}
	if r := rune(out[0]); unicode.IsDigit(r) {
		out = "_" + out
	}
	return out
}
