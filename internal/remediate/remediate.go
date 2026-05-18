// Package remediate generates structured fix-it artifacts (Terraform
// blocks, kubectl patches, cloud-CLI commands, Ansible plays, Helm
// overlays, bash one-liners) from compliancekit Findings. v0.15+.
//
// Remediation is GENERATION, not APPLICATION. Per ADR-006 the binary
// never mutates infrastructure on its own — `--apply-fix` is the v2.x
// trust gate, intentionally a separate decision. Every Snippet this
// package emits is something the operator copy-pastes (or wires into
// a PR they review). The flow is:
//
//	scanner emits Finding → Strategy registered for finding.CheckID
//	→ Render(finding, format) → Snippet (Content + Verify + Rollback)
//	→ writer drops Snippet onto disk inside the evidence pack.
//
// ADR-011 codifies the architectural shape. Highlights:
//   - One Strategy may handle multiple CheckIDs and multiple Formats.
//   - A Strategy declares a RiskClass (safe/review/manual) so operators
//     and the POA&M emitter know which findings need a human in the loop.
//   - Strategies live in per-format subpackages
//     (internal/remediate/{terraform,kubectl,awscli,gcloud,azcli,doctl,
//     hcloud,helm,ansible,bash}) and self-register via package init.
//   - The CLI side-effect-imports each subpackage in
//     internal/cli/remediate.go; tests import only what they exercise.
//
// What this package is NOT:
//   - It does not apply fixes (ADR-006).
//   - It does not run arbitrary user-supplied templates — every Strategy
//     is hand-written Go so the safety boundary is statically auditable.
//   - It does not invent CheckIDs; if a CheckID has no registered
//     Strategy the finding falls through to the POA&M emitter
//     (internal/remediate/poam) for manual-action capture.
package remediate

import (
	"errors"
	"fmt"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Format identifies one remediation output language. Operators select
// it via `compliancekit remediate --format=<value>` or get every format
// the strategies support via `--format=all`.
type Format string

const (
	// FormatBash emits POSIX-sh one-liners. Always available as a
	// fallback when a more structured format isn't supported for
	// a given CheckID.
	FormatBash Format = "bash"

	// FormatTerraform emits HCL fragments suitable for dropping into
	// an existing TF root module. Strategies aim for surgical fixes
	// (`aws_s3_bucket_public_access_block`-style focused blocks)
	// rather than full module rewrites.
	FormatTerraform Format = "terraform"

	// FormatKubectl emits `kubectl patch` commands plus the YAML
	// manifest equivalent so operators using GitOps (Argo / Flux)
	// can patch their repo directly.
	FormatKubectl Format = "kubectl"

	// FormatHelm emits values.yaml overlay snippets. Useful when the
	// offending manifest is owned by a third-party Helm chart and
	// editing the rendered output would be lost on next upgrade.
	FormatHelm Format = "helm"

	// FormatAnsible emits playbook task fragments. Used by Linux/CIS
	// strategies because hosts are the audience that already ships
	// Ansible configuration management at scale.
	FormatAnsible Format = "ansible"

	// FormatAWSCLI emits `aws <service> ...` commands. Live-cloud
	// fixes for AWS findings where the operator cannot or will not
	// route through Terraform.
	FormatAWSCLI Format = "aws-cli"

	// FormatGCloud emits `gcloud <service> ...` commands.
	FormatGCloud Format = "gcloud"

	// FormatAzureCLI emits `az <service> ...` commands.
	FormatAzureCLI Format = "az-cli"

	// FormatDoctl emits `doctl <service> ...` commands. DigitalOcean.
	FormatDoctl Format = "doctl"

	// FormatHcloud emits `hcloud <service> ...` commands. Hetzner.
	FormatHcloud Format = "hcloud"
)

// AllFormats is the canonical iteration order — bash first (fallback),
// then IaC, then cloud-CLI families. Stable for CLI output and tests.
var AllFormats = []Format{
	FormatBash,
	FormatTerraform,
	FormatKubectl,
	FormatHelm,
	FormatAnsible,
	FormatAWSCLI,
	FormatGCloud,
	FormatAzureCLI,
	FormatDoctl,
	FormatHcloud,
}

// String implements fmt.Stringer so Format flows through fmt.Sprintf
// in errors and runbook lines without ceremony.
func (f Format) String() string { return string(f) }

// ParseFormat normalizes a user-supplied format string. Accepts the
// canonical identifiers above plus a few aliases ("tf" → terraform,
// "k8s" → kubectl, "aws" → aws-cli) so the CLI is forgiving without
// allowing typos to silently pick the wrong language.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "bash", "sh":
		return FormatBash, nil
	case "terraform", "tf", "hcl":
		return FormatTerraform, nil
	case "kubectl", "k8s", "kubernetes":
		return FormatKubectl, nil
	case "helm":
		return FormatHelm, nil
	case "ansible", "playbook":
		return FormatAnsible, nil
	case "aws-cli", "aws", "awscli":
		return FormatAWSCLI, nil
	case "gcloud", "gcp":
		return FormatGCloud, nil
	case "az-cli", "az", "azure", "azurecli":
		return FormatAzureCLI, nil
	case "doctl", "do":
		return FormatDoctl, nil
	case "hcloud", "hetzner":
		return FormatHcloud, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownFormat, s)
}

// RiskClass tells the operator how much hand-holding a remediation
// needs. Strategies declare this; the runbook + POA&M emitter use it
// to route findings to the right column.
type RiskClass string

const (
	// RiskSafe means applying the snippet has no expected blast
	// radius: no service disruption, no data loss, no behavior
	// change beyond the security posture. Examples: enable
	// encryption-at-rest, attach a logging policy, set a tag.
	RiskSafe RiskClass = "safe"

	// RiskReview means applying changes visible behavior. The
	// operator should read the snippet before applying. Examples:
	// restrict a security group, narrow IAM permissions, set a
	// stricter pod-security context.
	RiskReview RiskClass = "review"

	// RiskManual means the fix cannot be expressed as a snippet
	// the operator copy-pastes — it requires out-of-band action.
	// Examples: rotate a leaked credential, renew a cert, revoke
	// an IAM user. POA&M routes these to the manual-action list.
	RiskManual RiskClass = "manual"
)

// String implements fmt.Stringer.
func (r RiskClass) String() string { return string(r) }

// Snippet is one remediation rendered in one Format. Strategies
// return Snippets from Render; writers persist them to disk inside
// the evidence pack.
//
// Content is the bytes the operator applies. VerifyCmd is a single
// bash one-liner an operator can run AFTER applying to confirm the
// fix landed (e.g. `aws s3api get-public-access-block ...`). It's
// optional but strongly encouraged — a remediation that can't be
// verified is hard to trust.
type Snippet struct {
	// CheckID is the finding this snippet remediates. Mirrors
	// compliancekit.Finding.CheckID exactly.
	CheckID string `json:"check_id"`

	// Format is the language of Content.
	Format Format `json:"format"`

	// Resource is a copy of the originating finding's ResourceRef.
	// Carried on the Snippet so downstream writers don't need to
	// re-join against the findings slice.
	Resource compliancekit.ResourceRef `json:"resource"`

	// Risk classifies how aggressive the change is. Operators
	// triage by risk before reading the body.
	Risk RiskClass `json:"risk"`

	// Idempotent reports whether re-applying the snippet leaves
	// system state unchanged. True for most Terraform / kubectl
	// patches; false for stateful operations like key rotation.
	Idempotent bool `json:"idempotent"`

	// Content is the executable text (HCL, bash, YAML, …). UTF-8.
	Content string `json:"content"`

	// VerifyCmd is an optional bash one-liner the operator can run
	// to confirm the fix landed. Empty when verification is not
	// expressible as a single command.
	VerifyCmd string `json:"verify_cmd,omitempty"`

	// RollbackCmd is an optional bash one-liner that undoes the
	// fix. Empty for safe / manual changes where rollback is
	// either unnecessary (safe) or non-trivial (manual).
	RollbackCmd string `json:"rollback_cmd,omitempty"`

	// Notes is short operator-facing prose: caveats, prerequisites
	// (e.g. "requires kms:CreateKey permission"), or context the
	// snippet itself doesn't communicate. Rendered above Content
	// in the runbook.
	Notes string `json:"notes,omitempty"`

	// Refs links to authoritative docs (provider guides, CIS
	// benchmark sections, CVE advisories).
	Refs []string `json:"refs,omitempty"`
}

// Strategy is the contract every remediation generator implements.
// One Strategy can handle several CheckIDs and emit several Formats;
// the registry indexes by CheckID and dispatches to Render.
//
// Implementations MUST be stateless: the same instance is reused
// across renders and across goroutines. Per-call state lives on the
// Finding and on the Snippet returned.
type Strategy interface {
	// Name is a short identifier for the strategy, e.g.
	// "aws-s3-public-access". Used in error messages, debug logs,
	// and the runbook's "rendered by" footer. Lowercase, kebab-case.
	Name() string

	// CheckIDs returns the catalog IDs this strategy handles. May
	// return ["*"] to register as a fallback for unmatched IDs —
	// fallbacks are tried after exact matches and only if no
	// concrete strategy claims the CheckID.
	CheckIDs() []string

	// Formats returns the Format values this strategy can render.
	// MUST be non-empty; a strategy that can render nothing should
	// not be registered.
	Formats() []Format

	// Render produces a Snippet for the given (finding, format)
	// pair. Returns ErrFormatUnsupported when format is not in
	// Formats(); returns a Snippet with Risk=RiskManual + empty
	// Content for findings the strategy recognizes but cannot
	// auto-remediate.
	Render(f compliancekit.Finding, format Format) (Snippet, error)
}

// Errors returned by the package + registry.
var (
	// ErrUnknownFormat is returned by ParseFormat when the input
	// is not one of the canonical names or aliases.
	ErrUnknownFormat = errors.New("remediate: unknown format")

	// ErrNoStrategy is returned by Registry.Render when no strategy
	// handles the finding's CheckID. The CLI translates this into
	// a POA&M manual-action entry rather than a hard error.
	ErrNoStrategy = errors.New("remediate: no strategy for check_id")

	// ErrFormatUnsupported is returned by Strategy.Render when the
	// strategy does not support the requested format. The registry
	// catches this and tries the next matching strategy.
	ErrFormatUnsupported = errors.New("remediate: format unsupported by strategy")
)
