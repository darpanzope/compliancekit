// Package kubectl implements remediate.Strategy renderers for the
// FormatKubectl output. Strategies emit two artifacts per Snippet:
//
//  1. A `kubectl patch` (or `kubectl create`) one-liner the operator
//     applies live for an immediate fix.
//  2. A full YAML manifest the operator commits to the GitOps repo
//     (Argo / Flux) so the fix survives a redeploy.
//
// Both forms appear in the Snippet's Content so the operator picks
// whichever matches their workflow. The first block is delimited by
// `# === kubectl patch ===` so a script can grep for it; the second
// block follows after `# === Manifest (GitOps) ===`.
//
// v0.15 starter coverage:
//   - Pod / container security context (runAsNonRoot, allowPrivEsc,
//     readOnlyRootFS, drop ALL capabilities, seccomp, host{Network,
//     PID,IPC} removal, privileged-flag removal, automount of SA token).
//   - Workload reliability (PDB, anti-affinity, min replicas,
//     RollingUpdate strategy, liveness/readiness probes).
//   - NetworkPolicy default-deny ingress + egress.
//   - Ingress (TLS, ingressClassName).
//   - Service (loadBalancerSourceRanges, externalIPs removal).
//   - Namespace policies (PodSecurity admission label, LimitRange,
//     ResourceQuota).
//   - RBAC (wildcards, cluster-admin escalation, anonymous bind)
//     route to RiskManual — replacement requires permission-audit
//     work that can't be expressed as a patch.
//
// Strategies pinned to FormatKubectl. The Helm overlay (Phase 8)
// covers Helm-deployed workloads via the same CheckIDs.
package kubectl

import (
	"fmt"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

// strategyFunc is the common shape of every renderer in this package.
type strategyFunc func(core.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatKubectl} }
func (s *strategy) Render(f core.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatKubectl {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

// defaultNamespace is the K8s default namespace name, used as a
// fallback when the finding's resource ID doesn't include one.
const defaultNamespace = "default"

// workloadFromResource extracts (kind, namespace, name) from a K8s
// finding's ResourceRef. Resources from the K8s collector use IDs
// shaped like `k8s.<kind>.<cluster>.<namespace>.<name>` — we crack
// the last two segments for namespace/name and use Type to recover
// the kind (`k8s.deployment` → "deployment").
//
// Returns ("Deployment", "default", "my-app") for a typical input.
// Falls back to sensible defaults when fields are missing so a
// strategy never panics on malformed input.
func workloadFromResource(f core.Finding) (kind, namespace, name string) {
	kind = "Deployment"
	if t := f.Resource.Type; strings.HasPrefix(t, "k8s.") {
		kind = capitalize(strings.TrimPrefix(t, "k8s."))
	}
	name = f.Resource.Name
	if name == "" {
		name = "REPLACE_ME"
	}
	// ID convention "k8s.<kind>.<cluster>.<ns>.<name>" — index -2 = ns.
	parts := strings.Split(f.Resource.ID, ".")
	if len(parts) >= 5 {
		namespace = parts[len(parts)-2]
	} else {
		namespace = defaultNamespace
	}
	return kind, namespace, name
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// patchAndManifest is the standard Content shape for kubectl
// strategies. It produces a two-block snippet: the patch command
// followed by the equivalent manifest. Both blocks carry a # title
// so operators see what they're applying.
func patchAndManifest(patchCmd, manifestYAML string) string {
	var sb strings.Builder
	sb.WriteString("# === kubectl patch (live) ===\n")
	sb.WriteString(patchCmd)
	sb.WriteString("\n\n# === Manifest (GitOps) ===\n")
	sb.WriteString(manifestYAML)
	return sb.String()
}

// kubectlPatch builds a strategic-merge `kubectl patch` command with
// the operator's namespace + workload + JSON patch body baked in.
// The patch body is provided as YAML (more readable in the runbook)
// and converted to single-line JSON-ish form for the command. We
// keep YAML on the command line via single quotes — works because
// kubectl accepts strategic-merge patches in either format.
func kubectlPatch(kind, namespace, name, patchYAML string) string {
	patch := strings.TrimSpace(patchYAML)
	return fmt.Sprintf(
		"kubectl patch %s %s -n %s --type=strategic --patch %s",
		strings.ToLower(kind),
		render.ShellQuote(name),
		render.ShellQuote(namespace),
		render.ShellQuote(patch),
	)
}
