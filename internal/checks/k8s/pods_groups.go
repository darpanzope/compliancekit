package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 4 — supplementalGroups check split out of pods_extra.go.

var CheckPodSupplementalGroups = core.Check{
	ID:           "k8s-pod-supplemental-groups-configured",
	Title:        "Pods with shared volumes should configure supplementalGroups",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "supplementalGroups grants the pod's processes membership in " +
		"the named GIDs for the lifetime of the container. Required for " +
		"NFS / CIFS / CSI volumes that authorize by group, and for any " +
		"image whose `id` reports group memberships the manifest hasn't " +
		"explicitly granted. Manual-verify pattern — info-only when unset.",
	Remediation: "Set `spec.securityContext.supplementalGroups: [<gid1>, <gid2>]` " +
		"to match the volume's group ownership. Required reading for any " +
		"workload mounting RWX NFS / CIFS.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "uid-gid", "manual-verify"},
	Scanner: "pods.SupplementalGroups",
}

func PodSupplementalGroups(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodSupplementalGroups.ID, Severity: CheckPodSupplementalGroups.Severity,
			Resource: p.Ref(), Tags: CheckPodSupplementalGroups.Tags,
		}
		sec, _ := p.Attributes["pod_security"].(map[string]any)
		raw, set := sec["supplemental_groups"]
		if !set {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("pod %q: supplementalGroups unset — verify per workload whether volume mounts need group authorization", podDesc(p))
		} else {
			groups, _ := raw.([]int64)
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: supplementalGroups=%v", podDesc(p), groups)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckPodSupplementalGroups, PodSupplementalGroups)
}
