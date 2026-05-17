package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 2 — reliability + ServiceAccount-projection pod checks
// split out of pods.go (904 → 3 files) to satisfy the 600-LoC
// invariant enforced by internal/repocheck.
//
// 4 checks: ResourceLimits / ResourceRequests / LivenessProbe /
// AutomountServiceAccountToken. Each uses helpers (violatingContainers,
// podFinding, podBooleanCheck, podDesc) from pods.go.

// ----- 11. Resource limits ----------------------------------------

var CheckPodResourceLimits = core.Check{
	ID:           "k8s-pod-resource-limits",
	Title:        "Containers should declare CPU and memory limits",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "A container without `resources.limits` can consume " +
		"all CPU and all memory on the node, starving every other " +
		"workload and frequently triggering OOM kills against neighbors. " +
		"Limits are the K8s noisy-neighbor primitive; running without " +
		"them is a denial-of-service hazard.",
	Remediation: "Set `resources.limits.cpu` and `resources.limits.memory` " +
		"on every container. Use a LimitRange on the namespace to give " +
		"defaults to workloads that don't declare their own.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6", "A.8.32"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "resources"},
	Scanner: "pods.ResourceLimits",
}

func PodResourceLimits(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			cpu, _ := c["has_cpu_limit"].(bool)
			mem, _ := c["has_memory_limit"].(bool)
			return !cpu || !mem
		})
		findings = append(findings, podFinding(CheckPodResourceLimits, p, bad,
			"containers without cpu/memory limits: %s",
			"all containers declare cpu/memory limits"))
	}
	return findings, nil
}

// ----- 12. Resource requests --------------------------------------

var CheckPodResourceRequests = core.Check{
	ID:           "k8s-pod-resource-requests",
	Title:        "Containers should declare CPU and memory requests",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`resources.requests` informs the scheduler how much " +
		"capacity to reserve for the pod. Without requests, the " +
		"scheduler treats the pod as having zero footprint, which leads " +
		"to over-subscribed nodes, evictions, and unpredictable " +
		"performance.",
	Remediation: "Set `resources.requests.cpu` and `resources.requests.memory` " +
		"on every container based on observed steady-state usage. The " +
		"Vertical Pod Autoscaler (recommender mode) is a good starting " +
		"point.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "resources"},
	Scanner: "pods.ResourceRequests",
}

func PodResourceRequests(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			cpu, _ := c["has_cpu_request"].(bool)
			mem, _ := c["has_memory_request"].(bool)
			return !cpu || !mem
		})
		findings = append(findings, podFinding(CheckPodResourceRequests, p, bad,
			"containers without cpu/memory requests: %s",
			"all containers declare cpu/memory requests"))
	}
	return findings, nil
}

// ----- 15. automountServiceAccountToken ---------------------------

var CheckPodAutomountSAToken = core.Check{
	ID:           "k8s-pod-automount-sa-token",
	Title:        "Pods that don't call the API should disable SA token mount",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Every pod by default has the namespace's default " +
		"ServiceAccount token mounted at /var/run/secrets/.../token. " +
		"Pods that never call the Kubernetes API gain nothing from that " +
		"token but expose it to any code-execution compromise. Setting " +
		"`automountServiceAccountToken: false` is the safe baseline; " +
		"opt back in per-workload that legitimately needs API access.",
	Remediation: "Set `automountServiceAccountToken: false` at the pod " +
		"level. For workloads that need API access, dedicate a " +
		"ServiceAccount with the minimum required Role and set " +
		"`automountServiceAccountToken: true` explicitly on the SA.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "pod-security", "service-account"},
	Scanner: "pods.AutomountSAToken",
}

func PodAutomountSAToken(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		mount, _ := p.Attributes["automount_sa_token"].(string)
		f := core.Finding{
			CheckID:  CheckPodAutomountSAToken.ID,
			Severity: CheckPodAutomountSAToken.Severity,
			Resource: p.Ref(),
			Tags:     CheckPodAutomountSAToken.Tags,
		}
		if mount == "false" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: SA token mount disabled", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: SA token mounted (automount=%s)", podDesc(p), mount)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 18. Liveness probe -----------------------------------------

var CheckPodLivenessProbe = core.Check{
	ID:           "k8s-pod-liveness-probe",
	Title:        "Containers should declare a liveness probe",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Without a livenessProbe, a container stuck in a " +
		"deadlock or wedged on a downstream timeout will sit in 'Ready' " +
		"forever — the kubelet has no signal to restart it. A simple " +
		"HTTP /healthz probe is enough to catch most production wedges " +
		"and is essentially free.",
	Remediation: "Add `livenessProbe` (HTTP GET against a /healthz " +
		"endpoint is the common pattern) to every long-running " +
		"container. Init and short-lived job containers are exempt.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "pod-security", "reliability"},
	Scanner: "pods.LivenessProbe",
}

func PodLivenessProbe(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			kind, _ := c["kind"].(string)
			if kind == "init" {
				return false
			}
			has, _ := c["has_liveness_probe"].(bool)
			return !has
		})
		findings = append(findings, podFinding(CheckPodLivenessProbe, p, bad,
			"containers without livenessProbe: %s",
			"all long-running containers have a livenessProbe"))
	}
	return findings, nil
}

func init() {
	core.Register(CheckPodResourceLimits, PodResourceLimits)
	core.Register(CheckPodResourceRequests, PodResourceRequests)
	core.Register(CheckPodAutomountSAToken, PodAutomountSAToken)
	core.Register(CheckPodLivenessProbe, PodLivenessProbe)
}
