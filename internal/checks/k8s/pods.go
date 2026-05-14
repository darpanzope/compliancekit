// Package k8s holds the Kubernetes check catalog. Each per-service
// file registers its checks via init() against the global core
// registry; the main binary and gencheckdocs both side-effect-import
// this package so the catalog is complete at scan/render time.
package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// Pod Security check IDs are grouped together so operators can
// include/exclude the whole family via the `k8s.pod-security` tag
// or per-check waivers.

// ----- 1. Privileged containers ---------------------------------

var CheckPodPrivileged = core.Check{
	ID:           "k8s-pod-privileged",
	Title:        "Pods should not run privileged containers",
	Severity:     core.SeverityCritical,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "A container with `securityContext.privileged: true` " +
		"runs with all Linux capabilities, full device access, and " +
		"SELinux/AppArmor disabled by default. A break-out from a " +
		"privileged pod gives the attacker root on the underlying " +
		"node and across every pod scheduled on it.",
	Remediation: "Set `securityContext.privileged: false` on every " +
		"container. If a workload needs hardware access (GPU, raw " +
		"disk), grant only the specific Linux capability it requires " +
		"via `securityContext.capabilities.add: [...]`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6", "CC6.8"},
		"iso27001": {"A.8.2", "A.8.9", "A.8.20"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "privileged"},
	Scanner: "pods.Privileged",
}

func PodPrivileged(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			v, ok := c["privileged"].(bool)
			return ok && v
		})
		findings = append(findings, podFinding(CheckPodPrivileged, p, bad,
			"runs privileged containers: %s",
			"no privileged containers"))
	}
	return findings, nil
}

// ----- 2. hostNetwork --------------------------------------------

var CheckPodHostNetwork = core.Check{
	ID:           "k8s-pod-host-network",
	Title:        "Pods should not use the host network",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`spec.hostNetwork: true` puts the pod in the node's " +
		"network namespace. It can bind to any node-local port, " +
		"sniff traffic on any node interface, and bypass NetworkPolicy " +
		"entirely. Only system add-ons (kube-proxy, CNI agents) need it.",
	Remediation: "Remove `spec.hostNetwork` (defaults to false). For " +
		"node-local services, use a `hostPort` declaration on a " +
		"specific container port instead — narrower blast radius.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.5"},
	},
	Tags:    []string{"k8s", "pod-security", "host-namespace"},
	Scanner: "pods.HostNetwork",
}

func PodHostNetwork(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return podBooleanCheck(g, CheckPodHostNetwork, "host_network",
		"uses host network namespace",
		"does not use host network"), nil
}

// ----- 3. hostPID -------------------------------------------------

var CheckPodHostPID = core.Check{
	ID:           "k8s-pod-host-pid",
	Title:        "Pods should not share the host PID namespace",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`spec.hostPID: true` lets the pod see every process " +
		"on the node — useful for debugging, dangerous for production. " +
		"An attacker with code execution in a hostPID pod can read " +
		"environment variables and /proc/<pid>/cmdline of every " +
		"other process on the node.",
	Remediation: "Remove `spec.hostPID` (defaults to false). For " +
		"diagnostic workloads, use `kubectl debug` or an ephemeral " +
		"debug container instead of a permanent hostPID-enabled pod.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "host-namespace"},
	Scanner: "pods.HostPID",
}

func PodHostPID(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return podBooleanCheck(g, CheckPodHostPID, "host_pid",
		"uses host PID namespace",
		"does not use host PID"), nil
}

// ----- 4. hostIPC -------------------------------------------------

var CheckPodHostIPC = core.Check{
	ID:           "k8s-pod-host-ipc",
	Title:        "Pods should not share the host IPC namespace",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`spec.hostIPC: true` shares the node's SysV IPC and " +
		"POSIX shared memory with the pod. Almost no production " +
		"workload needs this; it exists for legacy unix-IPC integrations.",
	Remediation: "Remove `spec.hostIPC` (defaults to false).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "host-namespace"},
	Scanner: "pods.HostIPC",
}

func PodHostIPC(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return podBooleanCheck(g, CheckPodHostIPC, "host_ipc",
		"uses host IPC namespace",
		"does not use host IPC"), nil
}

// ----- 5. Privilege escalation -----------------------------------

var CheckPodAllowPrivilegeEscalation = core.Check{
	ID:           "k8s-pod-allow-privilege-escalation",
	Title:        "Containers should not allow privilege escalation",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "`allowPrivilegeEscalation: true` (or unset, which " +
		"defaults to true) means the container's process can gain " +
		"more privileges than its parent via setuid binaries or " +
		"capabilities. The hardened baseline sets this to false on " +
		"every container.",
	Remediation: "Add `securityContext.allowPrivilegeEscalation: false` " +
		"to every container spec. Enforce cluster-wide via the " +
		"Pod Security Admission `restricted` profile.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.9"},
		"cis-v8":   {"4.7", "6.3"},
	},
	Tags:    []string{"k8s", "pod-security", "privilege-escalation"},
	Scanner: "pods.AllowPrivilegeEscalation",
}

func PodAllowPrivilegeEscalation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			v, ok := c["allow_priv_escalation"].(bool)
			// nil treated as the K8s default of true.
			return !ok || v
		})
		findings = append(findings, podFinding(CheckPodAllowPrivilegeEscalation, p, bad,
			"containers allow privilege escalation: %s",
			"all containers set allowPrivilegeEscalation=false"))
	}
	return findings, nil
}

// ----- 6. Run as non-root ----------------------------------------

var CheckPodRunAsNonRoot = core.Check{
	ID:           "k8s-pod-run-as-non-root",
	Title:        "Containers should run as a non-root user",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Containers default to running as the image's USER, " +
		"which for many community images is root. A root process " +
		"compromised inside the container has more useful capabilities " +
		"to chain into a node compromise. Setting `runAsNonRoot: true` " +
		"makes the kubelet refuse to start the pod if the image's UID " +
		"is 0.",
	Remediation: "Set `securityContext.runAsNonRoot: true` at the pod " +
		"or container level, and set `runAsUser` to a non-zero UID. " +
		"Rebuild images with a non-root USER if needed.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"4.7", "6.7"},
	},
	Tags:    []string{"k8s", "pod-security", "root"},
	Scanner: "pods.RunAsNonRoot",
}

func PodRunAsNonRoot(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		podSet, podVal := podRunAsNonRoot(p)
		bad := violatingContainers(p, func(c map[string]any) bool {
			return !containerRunsAsNonRoot(c, podSet, podVal)
		})
		findings = append(findings, podFinding(CheckPodRunAsNonRoot, p, bad,
			"containers may run as root: %s",
			"all containers run as non-root"))
	}
	return findings, nil
}

// ----- 7. Read-only root filesystem ------------------------------

var CheckPodReadOnlyRootFS = core.Check{
	ID:           "k8s-pod-readonly-root-fs",
	Title:        "Containers should use a read-only root filesystem",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "A writable root filesystem lets a compromised process " +
		"drop persistent malware, rewrite system binaries, or fill the " +
		"disk. Setting `readOnlyRootFilesystem: true` forces apps to " +
		"declare writable mounts explicitly via emptyDir or PVCs, " +
		"which is also a clarity win at review time.",
	Remediation: "Set `securityContext.readOnlyRootFilesystem: true`. " +
		"Mount `emptyDir` volumes for paths the app actually writes " +
		"to (typically /tmp, /var/run, sometimes /var/log).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.8"},
		"iso27001": {"A.8.13", "A.8.32"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "immutable"},
	Scanner: "pods.ReadOnlyRootFS",
}

func PodReadOnlyRootFS(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			v, ok := c["read_only_root_fs"].(bool)
			return !ok || !v
		})
		findings = append(findings, podFinding(CheckPodReadOnlyRootFS, p, bad,
			"containers without readOnlyRootFilesystem=true: %s",
			"all containers use a read-only root"))
	}
	return findings, nil
}

// ----- 8. Capabilities not dropped -------------------------------

var CheckPodCapabilitiesDropAll = core.Check{
	ID:           "k8s-pod-capabilities-drop-all",
	Title:        "Containers should drop all Linux capabilities by default",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Containers inherit a default Linux capability set " +
		"from the runtime, including CHOWN, DAC_OVERRIDE, FSETID, " +
		"KILL, SETUID, and others. Dropping ALL and then adding back " +
		"only what is needed (the restricted PSA profile requires this) " +
		"is the canonical hardening baseline.",
	Remediation: "Add `securityContext.capabilities.drop: [ALL]` to " +
		"every container. Then add the minimum needed back via " +
		"`capabilities.add`; many web apps need none.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.9"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "capabilities"},
	Scanner: "pods.CapabilitiesDropAll",
}

func PodCapabilitiesDropAll(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			drop, _ := c["capabilities_drop"].([]string)
			for _, cap := range drop {
				if strings.EqualFold(cap, "ALL") {
					return false
				}
			}
			return true
		})
		findings = append(findings, podFinding(CheckPodCapabilitiesDropAll, p, bad,
			"containers do not drop ALL capabilities: %s",
			"all containers drop ALL capabilities"))
	}
	return findings, nil
}

// ----- 9. Dangerous capabilities added ---------------------------

var CheckPodDangerousCapabilities = core.Check{
	ID:           "k8s-pod-dangerous-capabilities",
	Title:        "Containers should not add high-risk Linux capabilities",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Capabilities like NET_ADMIN, SYS_ADMIN, SYS_PTRACE, " +
		"SYS_MODULE, and BPF give the container near-root access to " +
		"network state, kernel internals, or arbitrary processes on " +
		"the node. Granting one of these is a legitimate but high-bar " +
		"choice; a workload that adds them without justification is a " +
		"posture failure.",
	Remediation: "Audit `capabilities.add` on every container. Keep only " +
		"NET_BIND_SERVICE (for binding to ports <1024) without further " +
		"review; everything else requires a written justification.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.9"},
		"cis-v8":   {"4.7", "6.3"},
	},
	Tags:    []string{"k8s", "pod-security", "capabilities"},
	Scanner: "pods.DangerousCapabilities",
}

func PodDangerousCapabilities(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	dangerous := map[string]struct{}{
		"NET_ADMIN": {}, "SYS_ADMIN": {}, "SYS_PTRACE": {},
		"SYS_MODULE": {}, "SYS_RAWIO": {}, "SYS_BOOT": {},
		"BPF": {}, "PERFMON": {}, "DAC_READ_SEARCH": {},
	}
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			add, _ := c["capabilities_add"].([]string)
			for _, cap := range add {
				if _, hit := dangerous[strings.ToUpper(cap)]; hit {
					return true
				}
			}
			return false
		})
		findings = append(findings, podFinding(CheckPodDangerousCapabilities, p, bad,
			"containers add dangerous capabilities: %s",
			"no containers add dangerous capabilities"))
	}
	return findings, nil
}

// ----- 10. Seccomp profile ----------------------------------------

var CheckPodSeccompProfile = core.Check{
	ID:           "k8s-pod-seccomp-profile",
	Title:        "Containers should set a non-default seccomp profile",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Without `seccompProfile`, containers run with the " +
		"container runtime's default seccomp policy, which on most " +
		"distributions still permits a large attack surface (chmod, " +
		"mount, unshare, keyctl, etc.). Setting type=RuntimeDefault " +
		"applies a curated allowlist; type=Localhost lets you point at " +
		"your own profile.",
	Remediation: "Set `securityContext.seccompProfile.type: " +
		"RuntimeDefault` at the pod level. Override per-container only " +
		"when a specific workload needs more syscalls.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.32"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "seccomp"},
	Scanner: "pods.SeccompProfile",
}

func PodSeccompProfile(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		podType := podSeccompType(p)
		bad := violatingContainers(p, func(c map[string]any) bool {
			t, _ := c["seccomp_type"].(string)
			if t == "" {
				t = podType
			}
			switch t {
			case "RuntimeDefault", "Localhost":
				return false
			default:
				return true
			}
		})
		findings = append(findings, podFinding(CheckPodSeccompProfile, p, bad,
			"containers without seccomp profile: %s",
			"all containers use a hardened seccomp profile"))
	}
	return findings, nil
}

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

// ----- 13. Image tag :latest --------------------------------------

var CheckPodImageTagLatest = core.Check{
	ID:           "k8s-pod-image-tag-latest",
	Title:        "Container images should not use the :latest tag",
	Severity:     core.SeverityMedium,
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

func PodImageTagLatest(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
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

var CheckPodImagePullPolicy = core.Check{
	ID:           "k8s-pod-image-pull-policy",
	Title:        "Containers with mutable tags should set imagePullPolicy=Always",
	Severity:     core.SeverityLow,
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

func PodImagePullPolicy(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
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

// ----- 16. hostPath volumes ---------------------------------------

var CheckPodHostPathVolume = core.Check{
	ID:           "k8s-pod-host-path-volume",
	Title:        "Pods should not mount sensitive hostPath volumes",
	Severity:     core.SeverityHigh,
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

func PodHostPathVolume(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		paths, _ := p.Attributes["host_path_volumes"].([]string)
		f := core.Finding{
			CheckID:  CheckPodHostPathVolume.ID,
			Severity: CheckPodHostPathVolume.Severity,
			Resource: p.Ref(),
			Tags:     CheckPodHostPathVolume.Tags,
		}
		if len(paths) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: no hostPath volumes", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: hostPath volumes mounted: %s", podDesc(p), strings.Join(paths, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 17. hostPort ------------------------------------------------

var CheckPodHostPort = core.Check{
	ID:           "k8s-pod-host-port",
	Title:        "Containers should not declare hostPort",
	Severity:     core.SeverityMedium,
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

func PodHostPort(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
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

// ----- helpers -----------------------------------------------------

func init() {
	core.Register(CheckPodPrivileged, PodPrivileged)
	core.Register(CheckPodHostNetwork, PodHostNetwork)
	core.Register(CheckPodHostPID, PodHostPID)
	core.Register(CheckPodHostIPC, PodHostIPC)
	core.Register(CheckPodAllowPrivilegeEscalation, PodAllowPrivilegeEscalation)
	core.Register(CheckPodRunAsNonRoot, PodRunAsNonRoot)
	core.Register(CheckPodReadOnlyRootFS, PodReadOnlyRootFS)
	core.Register(CheckPodCapabilitiesDropAll, PodCapabilitiesDropAll)
	core.Register(CheckPodDangerousCapabilities, PodDangerousCapabilities)
	core.Register(CheckPodSeccompProfile, PodSeccompProfile)
	core.Register(CheckPodResourceLimits, PodResourceLimits)
	core.Register(CheckPodResourceRequests, PodResourceRequests)
	core.Register(CheckPodImageTagLatest, PodImageTagLatest)
	core.Register(CheckPodImagePullPolicy, PodImagePullPolicy)
	core.Register(CheckPodAutomountSAToken, PodAutomountSAToken)
	core.Register(CheckPodHostPathVolume, PodHostPathVolume)
	core.Register(CheckPodHostPort, PodHostPort)
	core.Register(CheckPodLivenessProbe, PodLivenessProbe)
}

// podBooleanCheck wraps the common pattern of a Pod-level boolean
// attribute that should be false.
func podBooleanCheck(g *core.ResourceGraph, check core.Check, attr, failMsg, passMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		v, _ := p.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: p.Ref(),
			Tags:     check.Tags,
		}
		if v {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: %s", podDesc(p), failMsg)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: %s", podDesc(p), passMsg)
		}
		findings = append(findings, f)
	}
	return findings
}

// violatingContainers returns the names of containers in the pod that
// match the predicate.
func violatingContainers(pod core.Resource, bad func(map[string]any) bool) []string {
	out := []string{}
	cs, _ := pod.Attributes["containers"].([]any)
	for _, ci := range cs {
		c, ok := ci.(map[string]any)
		if !ok {
			continue
		}
		if bad(c) {
			if name, ok := c["name"].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

// podFinding builds a Pass/Fail finding for the pod based on whether
// any violating containers were found.
func podFinding(check core.Check, pod core.Resource, bad []string, failTmpl, passMsg string) core.Finding {
	f := core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: pod.Ref(),
		Tags:     check.Tags,
	}
	if len(bad) > 0 {
		f.Status = core.StatusFail
		f.Message = fmt.Sprintf("pod %q: "+failTmpl, podDesc(pod), strings.Join(bad, ", "))
	} else {
		f.Status = core.StatusPass
		f.Message = fmt.Sprintf("pod %q: %s", podDesc(pod), passMsg)
	}
	return f
}

// podDesc renders "ns/name" for finding messages.
func podDesc(pod core.Resource) string {
	ns, _ := pod.Attributes["namespace"].(string)
	if ns == "" {
		return pod.Name
	}
	return ns + "/" + pod.Name
}

// podRunAsNonRoot returns (set, value) for the pod-level securityContext.
func podRunAsNonRoot(pod core.Resource) (set, val bool) {
	sec, ok := pod.Attributes["pod_security"].(map[string]any)
	if !ok {
		return false, false
	}
	v, ok := sec["run_as_non_root"].(bool)
	return ok, v
}

// containerRunsAsNonRoot returns true when a container is provably
// non-root: either its own runAsNonRoot=true, or the pod-level
// runAsNonRoot=true, or runAsUser is a non-zero positive integer.
func containerRunsAsNonRoot(c map[string]any, podSet, podVal bool) bool {
	if v, ok := c["run_as_non_root"].(bool); ok {
		return v
	}
	if u, ok := c["run_as_user"].(int64); ok {
		return u > 0
	}
	if podSet {
		return podVal
	}
	return false
}

// podSeccompType returns the pod-level seccomp type or empty if unset.
func podSeccompType(pod core.Resource) string {
	sec, ok := pod.Attributes["pod_security"].(map[string]any)
	if !ok {
		return ""
	}
	t, _ := sec["seccomp_type"].(string)
	return t
}
