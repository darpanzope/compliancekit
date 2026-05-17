package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 2 — workload reliability deepening. 12 checks covering
// probe coverage / ephemeral-storage limits / topology spread / image
// digest pinning / explicit termination grace. Complements the v0.11
// controllers.go (which owns PDB / anti-affinity / min-replicas /
// rolling-update / DaemonSet).

// ----- 1. readiness probe ------------------------------------------

var CheckPodReadinessProbe = core.Check{
	ID:           "k8s-pod-readiness-probe",
	Title:        "Containers should declare a readiness probe",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "Without a readiness probe the kube-apiserver assumes a pod " +
		"is ready as soon as the kubelet reports Running. That puts traffic " +
		"on instances that haven't finished initialization — observable as " +
		"timeouts the moment a Deployment scales up. Each application " +
		"container should declare a readiness probe (HTTP / TCP / exec).",
	Remediation: "Add `readinessProbe.httpGet.path: /healthz` (or TCP) to " +
		"every container in the pod spec. Distinct from livenessProbe — " +
		"a failing liveness probe restarts the container; a failing " +
		"readiness probe removes it from Service endpoints but keeps it " +
		"running for debug.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "probes"},
	Scanner: "reliability.ReadinessProbe",
}

func PodReadinessProbe(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			if k, _ := c["kind"].(string); k == "init" {
				return false // init-containers don't need readiness probes
			}
			has, _ := c["has_readiness_probe"].(bool)
			return !has
		})
		findings = append(findings, podFinding(CheckPodReadinessProbe, p, bad,
			"missing readiness probes on: %s",
			"all containers have readiness probes"))
	}
	return findings, nil
}

// ----- 2. startup probe (slow-starting workloads) -------------------

var CheckPodStartupProbe = core.Check{
	ID:           "k8s-pod-startup-probe-for-slow-start",
	Title:        "Slow-starting containers should declare a startup probe",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "A startup probe disables liveness + readiness checks until " +
		"it succeeds. Without it, slow-starting containers (JVM, .NET, " +
		"large model loads) get killed by liveness probes before they're " +
		"ready. Info-level — required only for slow-start workloads, not " +
		"every pod. The check flags pods that have liveness but no startup " +
		"probe, leaving the decision to the operator.",
	Remediation: "Add a startupProbe with a generous failureThreshold × " +
		"periodSeconds (e.g. failureThreshold: 30, periodSeconds: 10 → " +
		"5-minute startup budget). Once it succeeds, the regular liveness " +
		"+ readiness probes take over.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "probes", "manual-verify"},
	Scanner: "reliability.StartupProbe",
}

func PodStartupProbe(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodStartupProbe.ID, Severity: CheckPodStartupProbe.Severity,
			Resource: p.Ref(), Tags: CheckPodStartupProbe.Tags,
		}
		missing := []string{}
		cs, _ := p.Attributes["containers"].([]any)
		for _, ci := range cs {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			if k, _ := c["kind"].(string); k == "init" {
				continue
			}
			hasLive, _ := c["has_liveness_probe"].(bool)
			hasStartup, _ := c["has_startup_probe"].(bool)
			if hasLive && !hasStartup {
				if n, ok := c["name"].(string); ok {
					missing = append(missing, n)
				}
			}
		}
		if len(missing) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: containers with livenessProbe also have a startupProbe (or no liveness probe to clash with)", podDesc(p))
		} else {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("pod %q: containers with livenessProbe lacking a startupProbe (audit per workload startup time): %s", podDesc(p), strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. ephemeral storage limit ----------------------------------

var CheckPodEphemeralStorageLimit = core.Check{
	ID:           "k8s-pod-ephemeral-storage-limit",
	Title:        "Containers should declare ephemeral-storage limits",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "ephemeral-storage covers the writable layer + emptyDir + " +
		"log writes. Unlimited ephemeral-storage means a runaway log loop " +
		"or zip-bomb tmpfile fills the node disk → kubelet evicts every " +
		"pod on the node. Setting an explicit limit makes the OOM-style " +
		"eviction local to the offending pod.",
	Remediation: "Set `resources.limits.ephemeral-storage: 1Gi` (or higher " +
		"per workload disk profile). Pair with a matching " +
		"`resources.requests.ephemeral-storage` so the scheduler reserves " +
		"the budget.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "resources", "ephemeral-storage"},
	Scanner: "reliability.EphemeralStorageLimit",
}

func PodEphemeralStorageLimit(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			has, _ := c["has_ephemeral_storage_limit"].(bool)
			return !has
		})
		findings = append(findings, podFinding(CheckPodEphemeralStorageLimit, p, bad,
			"missing ephemeral-storage limits on: %s",
			"all containers have ephemeral-storage limits"))
	}
	return findings, nil
}

// ----- 4. topology spread constraints ------------------------------

var CheckPodTopologySpread = core.Check{
	ID:           "k8s-pod-topology-spread-constraints",
	Title:        "Multi-replica pods should declare topologySpreadConstraints",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "topologySpreadConstraints tells the scheduler how to fan " +
		"pods across zones / hosts. Without it, the default scheduler can " +
		"pack every replica on a single node — an entire workload goes " +
		"down with one node failure. anti-affinity is the older " +
		"alternative; topology spread is the modern one with finer control " +
		"(skew, whenUnsatisfiable).",
	Remediation: "Add `topologySpreadConstraints: [{maxSkew: 1, " +
		"topologyKey: topology.kubernetes.io/zone, whenUnsatisfiable: " +
		"DoNotSchedule, labelSelector: {matchLabels: {app: <name>}}}]`. " +
		"Use ScheduleAnyway in dev, DoNotSchedule in prod.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "topology"},
	Scanner: "reliability.TopologySpread",
}

func PodTopologySpread(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodTopologySpread.ID, Severity: CheckPodTopologySpread.Severity,
			Resource: p.Ref(), Tags: CheckPodTopologySpread.Tags,
		}
		ns, _ := p.Attributes["namespace"].(string)
		if ns == "kube-system" {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("pod %q: kube-system pods use cluster-managed scheduling", podDesc(p))
			findings = append(findings, f)
			continue
		}
		count, _ := p.Attributes["topology_spread_constraints"].(int)
		if count == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: no topologySpreadConstraints set", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: topologySpreadConstraints count=%d", podDesc(p), count)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. image digest pinning -------------------------------------

var CheckPodImageDigestPinned = core.Check{
	ID:           "k8s-pod-image-digest-pinned",
	Title:        "Containers should pin images by sha256 digest",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Image references should include a `@sha256:...` digest. " +
		"Tags — including :latest, semver tags, and date tags — are " +
		"mutable on the registry side: a registry owner can push a new " +
		"image at an existing tag and every pull thereafter gets the new " +
		"content. Pinning the digest defeats the supply-chain attack class " +
		"(Codecov, SolarWinds, etc.).",
	Remediation: "Reference images by digest: `ghcr.io/org/app@sha256:abc...`. " +
		"Use cosign verify-and-resolve in CI to translate a verified tag " +
		"into the corresponding digest before pushing the manifest. Build " +
		"systems that update images automatically (Renovate, dependabot) " +
		"can handle digest pinning without manual rewrites.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.6", "7.1", "16.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "image"},
	Scanner: "supplychain.ImageDigestPinned",
}

func PodImageDigestPinned(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			pinned, _ := c["image_digest_pinned"].(bool)
			return !pinned
		})
		findings = append(findings, podFinding(CheckPodImageDigestPinned, p, bad,
			"images not pinned by sha256 digest on: %s",
			"all images pinned by sha256 digest"))
	}
	return findings, nil
}

// ----- 6. termination grace period set -----------------------------

var CheckPodTerminationGrace = core.Check{
	ID:           "k8s-pod-termination-grace-period-explicit",
	Title:        "Pods should set terminationGracePeriodSeconds explicitly",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "The k8s default (30s) is wrong for almost every workload: " +
		"too short for slow-draining databases / cache flushes, way too " +
		"long for batch jobs. Setting an explicit value makes the shutdown " +
		"budget intentional + observable per workload. Production " +
		"databases typically need 60-300s; stateless web tier 10-30s; " +
		"batch jobs 0-5s.",
	Remediation: "Set `spec.terminationGracePeriodSeconds: <N>` matching " +
		"the workload's drain time. Pair with preStop hooks for " +
		"graceful-shutdown signaling.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "lifecycle"},
	Scanner: "reliability.TerminationGracePeriod",
}

func PodTerminationGrace(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodTerminationGrace.ID, Severity: CheckPodTerminationGrace.Severity,
			Resource: p.Ref(), Tags: CheckPodTerminationGrace.Tags,
		}
		grace, _ := p.Attributes["termination_grace_period"].(int64)
		if grace == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: terminationGracePeriodSeconds unset (defaults to 30s — rarely right for the workload)", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: terminationGracePeriodSeconds=%d", podDesc(p), grace)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. init-container resource limits ---------------------------

var CheckInitContainerResources = core.Check{
	ID:           "k8s-pod-init-container-resource-limits",
	Title:        "Init containers should declare CPU + memory limits",
	Severity:     core.SeverityLow,
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

func PodInitContainerResources(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckInitContainerResources.ID, Severity: CheckInitContainerResources.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerResources.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = core.StatusSkip
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
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers have CPU + memory limits", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers missing limits: %s", podDesc(p), strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. init-container readonly root fs --------------------------

var CheckInitContainerReadonlyFS = core.Check{
	ID:           "k8s-pod-init-container-readonly-rootfs",
	Title:        "Init containers should declare readOnlyRootFilesystem",
	Severity:     core.SeverityLow,
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

func PodInitContainerReadonlyFS(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckInitContainerReadonlyFS.ID, Severity: CheckInitContainerReadonlyFS.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerReadonlyFS.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = core.StatusSkip
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
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers have readOnlyRootFilesystem", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers without readOnlyRootFilesystem: %s", podDesc(p), strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 9. init-container privilege escalation ---------------------

var CheckInitContainerPrivEsc = core.Check{
	ID:           "k8s-pod-init-container-no-priv-escalation",
	Title:        "Init containers should disable allowPrivilegeEscalation",
	Severity:     core.SeverityMedium,
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

func PodInitContainerPrivEsc(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckInitContainerPrivEsc.ID, Severity: CheckInitContainerPrivEsc.Severity,
			Resource: p.Ref(), Tags: CheckInitContainerPrivEsc.Tags,
		}
		count, _ := p.Attributes["init_container_count"].(int)
		if count == 0 {
			f.Status = core.StatusSkip
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
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: all init containers disable allowPrivilegeEscalation", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: init containers allowing priv escalation (or unset): %s", podDesc(p), strings.Join(bad, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 10. container preStop hook (drain on shutdown) -------------

var CheckPodPreStopHook = core.Check{
	ID:           "k8s-pod-prestop-hook-for-graceful-drain",
	Title:        "Long-lived containers should declare a preStop hook",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "preStop runs before SIGTERM during graceful shutdown — " +
		"the place to deregister from service discovery / flush buffers / " +
		"close DB connections. Without it, the pod takes its " +
		"terminationGracePeriod to SIGKILL with whatever in-flight requests " +
		"happened to be on the wire. Info-only since preStop is workload-" +
		"specific — the check surfaces pods without one for operator review.",
	Remediation: "Add a preStop hook — typically `lifecycle.preStop.exec` " +
		"calling the app's shutdown endpoint, or `lifecycle.preStop.httpGet`. " +
		"Pair with terminationGracePeriodSeconds wide enough for the hook " +
		"to complete.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "lifecycle", "manual-verify"},
	Scanner: "reliability.PreStopHook",
}

func PodPreStopHook(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		// All v0.21 phase 2 checks return Info-grade since preStop hooks
		// are workload-specific. We surface every pod for audit — the
		// auditor decides per workload whether one is required.
		f := core.Finding{
			CheckID: CheckPodPreStopHook.ID, Severity: CheckPodPreStopHook.Severity,
			Resource: p.Ref(), Tags: CheckPodPreStopHook.Tags,
			Status:  core.StatusError,
			Message: fmt.Sprintf("pod %q: audit preStop hooks per container (kubectl get pod -n <ns> <name> -o jsonpath='{.spec.containers[*].lifecycle.preStop}')", podDesc(p)),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 11. owner ref present (orphaned pods) ----------------------

var CheckPodHasOwnerRef = core.Check{
	ID:           "k8s-pod-has-owner-ref",
	Title:        "Standalone pods (no owner reference) should be reviewed",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "reliability",
	ResourceType: k8scol.PodType,
	Description: "A pod without an ownerReference (Deployment / StatefulSet / " +
		"DaemonSet / Job / CronJob) survives an apiserver restart but does " +
		"NOT get rescheduled on node failure. Used as a one-off debug " +
		"primitive (`kubectl run --restart=Never`); usually a mistake in " +
		"production where the operator forgot to wrap the spec in a " +
		"controller.",
	Remediation: "Wrap the pod spec in a Deployment / StatefulSet / Job " +
		"controller. For genuinely ephemeral debug, use `kubectl debug` " +
		"or namespaced `kubectl run --rm -it --restart=Never`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "reliability", "lifecycle"},
	Scanner: "reliability.HasOwnerRef",
}

func PodHasOwnerRef(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodHasOwnerRef.ID, Severity: CheckPodHasOwnerRef.Severity,
			Resource: p.Ref(), Tags: CheckPodHasOwnerRef.Tags,
		}
		kind, _ := p.Attributes["owner_kind"].(string)
		ns, _ := p.Attributes["namespace"].(string)
		switch {
		case ns == "kube-system":
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("pod %q: kube-system static pods often have no controller", podDesc(p))
		case kind == "":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: no owner reference (orphan — won't be rescheduled on node failure)", podDesc(p))
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: owned by %s", podDesc(p), kind)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 12. host ports (already exists at container level — add pod-level summary)

var CheckPodNoHostPorts = core.Check{
	ID:           "k8s-pod-no-host-ports",
	Title:        "Pods should not bind hostPort (narrower than hostNetwork but same risk class)",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "hostPort opens a port on every node the pod can be scheduled to " +
		"— even nodes where the pod isn't running. Bypasses NetworkPolicy " +
		"+ Service abstraction. Sometimes legitimate for ingress controllers " +
		"with hostNetwork unavailable, but in those cases the host-firewall " +
		"protection has to be set up manually. CIS recommends auditing " +
		"every use.",
	Remediation: "Remove `containers[].ports[].hostPort`. For node-local " +
		"ingress, use a NodePort Service or a hostNetwork pod with an " +
		"explicit nftables/iptables rule. Audit any remaining hostPort " +
		"usage against your network-perimeter policy.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.5"},
	},
	Tags:    []string{"k8s", "pod-security", "host-namespace", "network"},
	Scanner: "podsecurity.NoHostPorts",
}

func PodNoHostPorts(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			ports, _ := c["host_ports"].([]int)
			return len(ports) > 0
		})
		findings = append(findings, podFinding(CheckPodNoHostPorts, p, bad,
			"hostPort bindings on: %s",
			"no hostPort bindings"))
	}
	return findings, nil
}

func init() {
	core.Register(CheckPodReadinessProbe, PodReadinessProbe)
	core.Register(CheckPodStartupProbe, PodStartupProbe)
	core.Register(CheckPodEphemeralStorageLimit, PodEphemeralStorageLimit)
	core.Register(CheckPodTopologySpread, PodTopologySpread)
	core.Register(CheckPodImageDigestPinned, PodImageDigestPinned)
	core.Register(CheckPodTerminationGrace, PodTerminationGrace)
	core.Register(CheckInitContainerResources, PodInitContainerResources)
	core.Register(CheckInitContainerReadonlyFS, PodInitContainerReadonlyFS)
	core.Register(CheckInitContainerPrivEsc, PodInitContainerPrivEsc)
	core.Register(CheckPodPreStopHook, PodPreStopHook)
	core.Register(CheckPodHasOwnerRef, PodHasOwnerRef)
	core.Register(CheckPodNoHostPorts, PodNoHostPorts)
}
