package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.22 phase 2 — image-discipline + host-namespace volume/port pod
// checks split out of pods.go (904 → 3 files).
//
// 4 checks: ImageTagLatest / ImagePullPolicy / HostPathVolume /
// HostPort. Uses helpers from pods.go.

// ----- 13. Image tag :latest --------------------------------------

var CheckPodImageTagLatest = compliancekit.Check{
	ID:           "k8s-pod-image-tag-latest",
	Title:        "Container images should not use the :latest tag",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`:latest` is a mutable, untracked tag — what runs on " +
		"Tuesday may not be what runs on Wednesday. It breaks rollback, " +
		"breaks reproducibility, and silently delivers supply-chain " +
		"updates without operator review. A pinned tag or, better, an " +
		"image digest is the only defensible choice in production.",
	Remediation: "Pin every image to a specific tag (`v1.2.3`) or a " +
		"digest (`@sha256:...`). Digests are tamper-proof; tags are not.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC8.1"},
		"iso27001": {"A.8.8", "A.8.30"},
		"cis-v8":   {"2.3", "16.4"},
	},
	Tags:    []string{"k8s", "pod-security", "supply-chain", "image"},
	Scanner: "pods.ImageTagLatest",
}

func PodImageTagLatest(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			tag, _ := c["image_tag"].(string)
			return tag == "latest" || tag == ""
		})
		findings = append(findings, podFinding(CheckPodImageTagLatest, p, bad,
			"containers using :latest or untagged images: %s",
			"all container images use pinned tags or digests"))
	}
	return findings, nil
}

// ----- 14. imagePullPolicy ----------------------------------------

var CheckPodImagePullPolicy = compliancekit.Check{
	ID:           "k8s-pod-image-pull-policy",
	Title:        "Containers with mutable tags should set imagePullPolicy=Always",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "When using a mutable tag (`:latest` or any non-pinned " +
		"tag), the cached image on a node can drift from the registry. " +
		"`imagePullPolicy: Always` forces the kubelet to consult the " +
		"registry on every pod start, defeating cache poisoning and " +
		"making rollouts deterministic. Pinned-digest images can use " +
		"IfNotPresent safely.",
	Remediation: "Either pin to a digest (preferred) or set " +
		"`imagePullPolicy: Always` on every container using a tag " +
		"that can mutate.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.8.30"},
		"cis-v8":   {"16.4"},
	},
	Tags:    []string{"k8s", "pod-security", "supply-chain", "image"},
	Scanner: "pods.ImagePullPolicy",
}

func PodImagePullPolicy(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			image, _ := c["image"].(string)
			tag, _ := c["image_tag"].(string)
			policy, _ := c["image_pull_policy"].(string)
			// Digest-pinned: IfNotPresent is fine.
			if strings.Contains(image, "@sha256:") {
				return false
			}
			if tag == "latest" || tag == "" {
				return policy != "Always"
			}
			// Pinned numeric tag: any policy is acceptable.
			return false
		})
		findings = append(findings, podFinding(CheckPodImagePullPolicy, p, bad,
			"containers with mutable tags missing imagePullPolicy=Always: %s",
			"image pull policies appropriate for each tag type"))
	}
	return findings, nil
}

// ----- 16. hostPath volumes ---------------------------------------

var CheckPodHostPathVolume = compliancekit.Check{
	ID:           "k8s-pod-host-path-volume",
	Title:        "Pods should not mount sensitive hostPath volumes",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`hostPath` mounts give the pod direct read/write " +
		"access to a path on the node's filesystem. A hostPath onto " +
		"/, /etc, /var/run/docker.sock, or /proc is a container escape " +
		"in slow motion. Even narrowly-scoped hostPath mounts are an " +
		"audit liability — there is almost always a better K8s primitive.",
	Remediation: "Replace hostPath with a CSI-provided PersistentVolume, " +
		"a ConfigMap, or a Secret depending on the use case. The " +
		"`local-path` CSI provisioner is the right substitute for " +
		"node-local persistent data.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.13", "A.8.20"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "host-fs"},
	Scanner: "pods.HostPathVolume",
}

func PodHostPathVolume(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		paths, _ := p.Attributes["host_path_volumes"].([]string)
		f := compliancekit.Finding{
			CheckID:  CheckPodHostPathVolume.ID,
			Severity: CheckPodHostPathVolume.Severity,
			Resource: p.Ref(),
			Tags:     CheckPodHostPathVolume.Tags,
		}
		if len(paths) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("pod %q: no hostPath volumes", podDesc(p))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("pod %q: hostPath volumes mounted: %s", podDesc(p), strings.Join(paths, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 17. hostPort ------------------------------------------------

var CheckPodHostPort = compliancekit.Check{
	ID:           "k8s-pod-host-port",
	Title:        "Containers should not declare hostPort",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "A container with `hostPort` binds to a port on the " +
		"underlying node, bypassing the Service abstraction and " +
		"NetworkPolicy. Two hostPort pods cannot land on the same node. " +
		"Only DaemonSets implementing node-local infrastructure (CNI " +
		"agents, log forwarders) have a legitimate need.",
	Remediation: "Remove `hostPort` from every container port. For " +
		"externally-reachable workloads, use a Service of type " +
		"NodePort or LoadBalancer.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5"},
	},
	Tags:    []string{"k8s", "pod-security", "network"},
	Scanner: "pods.HostPort",
}

func PodHostPort(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			ports, _ := c["host_ports"].([]int)
			return len(ports) > 0
		})
		findings = append(findings, podFinding(CheckPodHostPort, p, bad,
			"containers declare hostPort: %s",
			"no containers declare hostPort"))
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckPodImageTagLatest, PodImageTagLatest)
	compliancekit.Register(CheckPodImagePullPolicy, PodImagePullPolicy)
	compliancekit.Register(CheckPodHostPathVolume, PodHostPathVolume)
	compliancekit.Register(CheckPodHostPort, PodHostPort)
}
