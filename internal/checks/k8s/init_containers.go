package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 4 — init-container reliability checks split out of
// reliability.go to satisfy the 600-LoC invariant.

var CheckInitContainerResources = compliancekit.Check{
	ID:           "k8s-pod-init-container-resource-limits",
	Title:        "Init containers should declare CPU + memory limits",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "Init containers run before the pod is ready + are easy to " +
		"forget when adding resource limits — CIS 5.x explicitly calls " +
		"out the init-container omission. Without limits, an init step " +
		"(git clone of a large repo, decompression) can exhaust node " +
		"memory before the main containers even start.",
	Remediation: "Add `resources.limits.cpu` + `resources.limits.memory` " +
		"to every initContainers[] entry — typically modest (100m / 64Mi).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"4.6", "11.2"},
	},
	Tags:    []string{"k8s", "reliability", "init-container", "resources"},
	Scanner: "reliability.InitContainerResources",
}

func PodInitContainerResources(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := compliancekit.Finding{
			CheckID: CheckInitContainerResources.ID, Severity: CheckInitContainerResources.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerResources.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("pod %q: no init containers", podDesc(p))
			findings = append(findings, f)
			continue
		}
		missing := []string{}
		cs, _ := p.Attributes["containers"].([]any)
		for _, ci := range cs {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			if k, _ := c["kind"].(string); k != "init" {
				continue
			}
			hasCPU, _ := c["has_cpu_limit"].(bool)
			hasMem, _ := c["has_memory_limit"].(bool)
			if !hasCPU || !hasMem {
				if n, _ := c["name"].(string); n != "" {
					missing = append(missing, n)
				}
			}
		}
		if len(missing) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers have CPU + memory limits", podDesc(p))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers missing limits: %s", podDesc(p), strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. init-container readonly root fs --------------------------

var CheckInitContainerReadonlyFS = compliancekit.Check{
	ID:           "k8s-pod-init-container-readonly-rootfs",
	Title:        "Init containers should declare readOnlyRootFilesystem",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Init containers are often given runtime tooling permissions " +
		"the main app doesn't need (git, curl, jq writing to /tmp). They " +
		"still need the same securityContext discipline — readOnlyRootFS " +
		"applied at the init-container level + emptyDir mount for /tmp " +
		"makes init-container compromise less useful to an attacker.",
	Remediation: "Add `securityContext.readOnlyRootFilesystem: true` to " +
		"every initContainers[] entry. Mount /tmp via a writable emptyDir " +
		"volume if the init step needs scratch space.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "init-container"},
	Scanner: "podsecurity.InitContainerReadonlyFS",
}

func PodInitContainerReadonlyFS(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := compliancekit.Finding{
			CheckID: CheckInitContainerReadonlyFS.ID, Severity: CheckInitContainerReadonlyFS.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerReadonlyFS.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("pod %q: no init containers", podDesc(p))
			findings = append(findings, f)
			continue
		}
		missing := []string{}
		cs, _ := p.Attributes["containers"].([]any)
		for _, ci := range cs {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			if k, _ := c["kind"].(string); k != "init" {
				continue
			}
			ro, _ := c["read_only_root_fs"].(bool)
			if !ro {
				if n, _ := c["name"].(string); n != "" {
					missing = append(missing, n)
				}
			}
		}
		if len(missing) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers have readOnlyRootFilesystem", podDesc(p))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers without readOnlyRootFilesystem: %s", podDesc(p), strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 9. init-container privilege escalation ---------------------

var CheckInitContainerPrivEsc = compliancekit.Check{
	ID:           "k8s-pod-init-container-no-priv-escalation",
	Title:        "Init containers should disable allowPrivilegeEscalation",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "allowPrivilegeEscalation defaults to true, which lets a " +
		"setuid binary in the init container gain root via the same mechanism " +
		"main containers are flagged for. Same posture for init as for " +
		"runtime containers.",
	Remediation: "Add `securityContext.allowPrivilegeEscalation: false` " +
		"to every initContainers[] entry.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "init-container"},
	Scanner: "podsecurity.InitContainerPrivEsc",
}

func PodInitContainerPrivEsc(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := compliancekit.Finding{
			CheckID: CheckInitContainerPrivEsc.ID, Severity: CheckInitContainerPrivEsc.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerPrivEsc.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("pod %q: no init containers", podDesc(p))
			findings = append(findings, f)
			continue
		}
		bad := []string{}
		cs, _ := p.Attributes["containers"].([]any)
		for _, ci := range cs {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			if k, _ := c["kind"].(string); k != "init" {
				continue
			}
			allow, set := c["allow_priv_escalation"].(bool)
			if !set || allow {
				if n, _ := c["name"].(string); n != "" {
					bad = append(bad, n)
				}
			}
		}
		if len(bad) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers disable allowPrivilegeEscalation", podDesc(p))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers allowing priv escalation (or unset): %s", podDesc(p), strings.Join(bad, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckInitContainerResources, PodInitContainerResources)
	compliancekit.Register(CheckInitContainerReadonlyFS, PodInitContainerReadonlyFS)
	compliancekit.Register(CheckInitContainerPrivEsc, PodInitContainerPrivEsc)
}
