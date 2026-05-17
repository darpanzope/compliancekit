package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 1 — pod-security deepening. 12 new checks covering the
// pod-spec dimensions CIS Kubernetes Benchmark §5 (Pod Security
// Standards) requires beyond the v0.11 baseline. Lives in a separate
// file to keep pods.go from breaching the 600-LoC invariant tightened
// in v0.22.
//
// Per the v0.21 parity ratchet, every check here ships with a bespoke
// kubectl strategy (see internal/remediate/kubectl/pod_security_extra.go).

// ----- 1. shareProcessNamespace --------------------------------------

var CheckPodShareProcessNamespace = core.Check{
	ID:           "k8s-pod-share-process-namespace",
	Title:        "Pods should not enable shareProcessNamespace",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "shareProcessNamespace=true puts every container in the " +
		"pod into a shared PID namespace. A compromise in any sidecar " +
		"then has /proc visibility into every other container's process " +
		"tree — credential scraping, signal sending, file-handle leak. " +
		"CIS Kubernetes Benchmark v1.x §5.2.x.",
	Remediation: "Remove `spec.shareProcessNamespace` (defaults to false). " +
		"If you need cross-container debugging, prefer ephemeral debug " +
		"containers (`kubectl debug -it ... --image=...`) over leaving " +
		"shareProcessNamespace=true in the manifest.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "namespace"},
	Scanner: "pods.ShareProcessNamespace",
}

func PodShareProcessNamespace(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodShareProcessNamespace.ID, Severity: CheckPodShareProcessNamespace.Severity,
			Resource: p.Ref(), Tags: CheckPodShareProcessNamespace.Tags,
		}
		v, set := p.Attributes["share_process_namespace"].(bool)
		switch {
		case !set:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: shareProcessNamespace unset (defaults to false)", podDesc(p))
		case v:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: shareProcessNamespace=true", podDesc(p))
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: shareProcessNamespace=false", podDesc(p))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. dnsPolicy --------------------------------------------------

var CheckPodDNSPolicy = core.Check{
	ID:           "k8s-pod-dns-policy-not-default",
	Title:        "Pods should not use dnsPolicy=Default (host resolver)",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "dnsPolicy=Default reads /etc/resolv.conf from the node — " +
		"pods inherit the host's DNS view, including any node-local DNS " +
		"that may resolve internal names a tenanted workload should not " +
		"see. ClusterFirst (the default) routes to the cluster DNS service " +
		"so policy lives in one place.",
	Remediation: "Set `spec.dnsPolicy: ClusterFirst` (or omit — that's " +
		"the default). Reserve Default for host-networked add-ons that " +
		"genuinely need the node resolver.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "dns"},
	Scanner: "pods.DNSPolicy",
}

func PodDNSPolicy(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodDNSPolicy.ID, Severity: CheckPodDNSPolicy.Severity,
			Resource: p.Ref(), Tags: CheckPodDNSPolicy.Tags,
		}
		policy, _ := p.Attributes["dns_policy"].(string)
		if policy == "Default" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: dnsPolicy=Default (host resolver)", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: dnsPolicy=%q", podDesc(p), policy)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. priorityClassName explicit --------------------------------

var CheckPodPriorityClass = core.Check{
	ID:           "k8s-pod-priority-class-explicit",
	Title:        "Production pods should set priorityClassName explicitly",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "An unset priorityClassName puts the pod at priority 0, " +
		"meaning it can be preempted by anything system-cluster-critical " +
		"or higher. Setting an explicit priority makes the eviction order " +
		"intentional — and lets the scheduler distinguish critical workloads " +
		"from best-effort under pressure.",
	Remediation: "Define a PriorityClass + reference it: " +
		"`spec.priorityClassName: <name>`. CIS recommends two named tiers " +
		"(`production`, `batch`) at minimum. Skipped by default for kube-system.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "pod-security", "scheduling"},
	Scanner: "pods.PriorityClass",
}

func PodPriorityClass(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodPriorityClass.ID, Severity: CheckPodPriorityClass.Severity,
			Resource: p.Ref(), Tags: CheckPodPriorityClass.Tags,
		}
		ns, _ := p.Attributes["namespace"].(string)
		if ns == "kube-system" {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("pod %q: kube-system pods use cluster-managed priority", podDesc(p))
			findings = append(findings, f)
			continue
		}
		pc, _ := p.Attributes["priority_class_name"].(string)
		if pc == "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: priorityClassName unset (defaults to priority 0)", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: priorityClassName=%q", podDesc(p), pc)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. hostUsers (k8s 1.28+) -------------------------------------

var CheckPodHostUsers = core.Check{
	ID:           "k8s-pod-host-users-disabled",
	Title:        "Pods should set hostUsers=false on k8s 1.30+",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "hostUsers=false (default on 1.30+ via UserNamespaces feature " +
		"gate) puts each pod in its own user namespace — UID 0 inside the " +
		"pod maps to an unprivileged UID on the host. Significant kernel " +
		"breakout mitigation. Setting explicit hostUsers: false is the " +
		"production-safe path while the default migrates across versions.",
	Remediation: "Add `spec.hostUsers: false`. Test workload compatibility " +
		"first — applications that mount host volumes with hard-coded UIDs " +
		"can break under user-namespace remapping.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "user-namespace"},
	Scanner: "pods.HostUsers",
}

func PodHostUsers(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodHostUsers.ID, Severity: CheckPodHostUsers.Severity,
			Resource: p.Ref(), Tags: CheckPodHostUsers.Tags,
		}
		v, set := p.Attributes["host_users"].(bool)
		switch {
		case !set:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: hostUsers unset — explicit `hostUsers: false` recommended for kernel-breakout mitigation", podDesc(p))
		case v:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: hostUsers=true (pod runs in host user namespace)", podDesc(p))
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: hostUsers=false (user-namespace isolated)", podDesc(p))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. pod-level fsGroup set -------------------------------------

var CheckPodFSGroup = core.Check{
	ID:           "k8s-pod-fs-group-set",
	Title:        "Pods with volumes should set securityContext.fsGroup",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "fsGroup makes the kubelet recursively chgrp emptyDir + " +
		"projected volumes to the named GID so non-root containers can " +
		"write to them. Without fsGroup, containers with " +
		"runAsNonRoot=true frequently fail with EACCES on volume mount " +
		"and operators reach for runAsUser=0 — undoing the security baseline.",
	Remediation: "Set `spec.securityContext.fsGroup: <gid>` (commonly 1000) " +
		"alongside runAsNonRoot=true so the volume permissions match the " +
		"non-root UID the containers run as.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "filesystem"},
	Scanner: "pods.FSGroup",
}

func PodFSGroup(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodFSGroup.ID, Severity: CheckPodFSGroup.Severity,
			Resource: p.Ref(), Tags: CheckPodFSGroup.Tags,
		}
		sec, _ := p.Attributes["pod_security"].(map[string]any)
		_, set := sec["fs_group"]
		if !set {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: securityContext.fsGroup unset", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: fsGroup=%v", podDesc(p), sec["fs_group"])
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. pod-level runAsGroup set ----------------------------------

var CheckPodRunAsGroup = core.Check{
	ID:           "k8s-pod-run-as-group-set",
	Title:        "Pods should set securityContext.runAsGroup",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Without explicit runAsGroup, processes inherit the GID baked " +
		"into the image (often root:0). Setting a non-zero runAsGroup makes " +
		"file-write-as-root impossible even if a container escapes runAsUser.",
	Remediation: "Set `spec.securityContext.runAsGroup: 1000` (or similar). " +
		"Apply at pod level so it inherits across every container.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "pod-security", "uid-gid"},
	Scanner: "pods.RunAsGroup",
}

func PodRunAsGroup(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodRunAsGroup.ID, Severity: CheckPodRunAsGroup.Severity,
			Resource: p.Ref(), Tags: CheckPodRunAsGroup.Tags,
		}
		sec, _ := p.Attributes["pod_security"].(map[string]any)
		raw, set := sec["run_as_group"]
		if !set {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: runAsGroup unset (image GID inherited)", podDesc(p))
			findings = append(findings, f)
			continue
		}
		gid, _ := raw.(int64)
		if gid == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: runAsGroup=0 (root group)", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: runAsGroup=%d", podDesc(p), gid)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. AppArmor profile set + not unconfined ---------------------

var CheckPodAppArmorProfile = core.Check{
	ID:           "k8s-pod-apparmor-profile-set",
	Title:        "Pods should set an AppArmor profile (not Unconfined)",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "AppArmor confines a container's syscall + filesystem reach " +
		"per profile. `runtime/default` is the upstream-shipped baseline; " +
		"`unconfined` removes confinement entirely. CIS recommends explicit " +
		"profile selection — `unset` makes posture ambiguous across nodes " +
		"that may or may not have a default profile loaded.",
	Remediation: "Annotate per container: " +
		"`container.apparmor.security.beta.kubernetes.io/<name>: runtime/default` " +
		"(or a custom profile). On k8s ≥ 1.30, prefer " +
		"`securityContext.appArmorProfile: {type: RuntimeDefault}` at the " +
		"container level.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "apparmor"},
	Scanner: "pods.AppArmorProfile",
}

func PodAppArmorProfile(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodAppArmorProfile.ID, Severity: CheckPodAppArmorProfile.Severity,
			Resource: p.Ref(), Tags: CheckPodAppArmorProfile.Tags,
		}
		profiles, _ := p.Attributes["apparmor_profile"].([]string)
		switch {
		case len(profiles) == 0:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: no AppArmor profile annotations set", podDesc(p))
		default:
			unconfined := []string{}
			for _, entry := range profiles {
				if strings.Contains(strings.ToLower(entry), "unconfined") {
					unconfined = append(unconfined, entry)
				}
			}
			if len(unconfined) > 0 {
				f.Status = core.StatusFail
				f.Message = fmt.Sprintf("pod %q: AppArmor unconfined on: %s", podDesc(p), strings.Join(unconfined, ", "))
			} else {
				f.Status = core.StatusPass
				f.Message = fmt.Sprintf("pod %q: AppArmor profiles set: %s", podDesc(p), strings.Join(profiles, ", "))
			}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. seccompProfile != Unconfined (strict) --------------------

var CheckPodSeccompNotUnconfined = core.Check{
	ID:           "k8s-pod-seccomp-not-unconfined",
	Title:        "Pods should not set seccompProfile.type=Unconfined",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Seccomp Unconfined removes the syscall allow-list entirely. " +
		"This complements `k8s-pod-seccomp-profile` (which fails when seccomp " +
		"is unset): a pod can have seccomp explicitly Unconfined and pass the " +
		"`is set` check while being strictly worse than the default. CIS " +
		"Pod Security Standards 'restricted' profile rejects Unconfined.",
	Remediation: "Set `securityContext.seccompProfile.type: RuntimeDefault` " +
		"(or `Localhost` with a per-node profile). Never use Unconfined " +
		"outside debug workflows.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "seccomp"},
	Scanner: "pods.SeccompNotUnconfined",
}

func PodSeccompNotUnconfined(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			t, _ := c["seccomp_type"].(string)
			return t == "Unconfined"
		})
		if podSeccompType(p) == "Unconfined" {
			bad = append([]string{"pod-level"}, bad...)
		}
		findings = append(findings, podFinding(CheckPodSeccompNotUnconfined, p, bad,
			"seccomp Unconfined on: %s",
			"no seccomp Unconfined"))
	}
	return findings, nil
}

// ----- 9. runtimeClassName explicit (manual-verify) ----------------

var CheckPodRuntimeClass = core.Check{
	ID:           "k8s-pod-runtime-class-explicit",
	Title:        "Untrusted workloads should set runtimeClassName (gVisor / Kata)",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "RuntimeClass lets per-pod runtime selection — gVisor for " +
		"shared-cluster multi-tenancy, Kata for hardware-isolation. Default " +
		"runc shares the host kernel. This check is information-only " +
		"(StatusInfo when unset) — production posture varies by cluster " +
		"shape; only enforce on clusters with multi-tenant or " +
		"untrusted-workload tiers.",
	Remediation: "Define a RuntimeClass + reference it: " +
		"`spec.runtimeClassName: gvisor`. RuntimeClass requires the CRI " +
		"to support the named handler (e.g. gVisor's runsc).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "pod-security", "runtime-class", "manual-verify"},
	Scanner: "pods.RuntimeClass",
}

func PodRuntimeClass(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodRuntimeClass.ID, Severity: CheckPodRuntimeClass.Severity,
			Resource: p.Ref(), Tags: CheckPodRuntimeClass.Tags,
		}
		rc, _ := p.Attributes["runtime_class_name"].(string)
		if rc == "" {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("pod %q: runtimeClassName unset — verify whether this workload tier requires sandbox runtime", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: runtimeClassName=%q", podDesc(p), rc)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 10. volume subPath usage (symlink-attack surface) -----------

var CheckPodVolumeSubpath = core.Check{
	ID:           "k8s-pod-volume-subpath-restricted",
	Title:        "Pods using volume subPath should be audited (CVE-2017-1002101 family)",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "volumeMount.subPath was the entry point for the symlink-race " +
		"CVE class (CVE-2017-1002101, CVE-2021-25741). Patched in modern " +
		"kubelets but the pattern remains risky against emptyDir + hostPath " +
		"volumes — a container that wins a TOCTOU race can escape the subPath " +
		"sandbox. Auditors flag every use for review.",
	Remediation: "Prefer separate Volume mounts at distinct mountPaths. If " +
		"subPath is required, ensure the underlying volume is configMap / " +
		"secret / downwardAPI (not emptyDir / hostPath) so the host filesystem " +
		"is not the substrate.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.7", "A.8.20"},
		"cis-v8":   {"7.1"},
	},
	Tags:    []string{"k8s", "pod-security", "subpath", "cve"},
	Scanner: "pods.VolumeSubpath",
}

func PodVolumeSubpath(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodVolumeSubpath.ID, Severity: CheckPodVolumeSubpath.Severity,
			Resource: p.Ref(), Tags: CheckPodVolumeSubpath.Tags,
		}
		mounts, _ := p.Attributes["volume_subpath_mounts"].([]string)
		if len(mounts) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: no subPath volume mounts", podDesc(p))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: subPath mounts in use (audit required): %s", podDesc(p), strings.Join(mounts, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 11. default service account use ----------------------------

var CheckPodDefaultSA = core.Check{
	ID:           "k8s-pod-default-service-account",
	Title:        "Pods should not use the 'default' ServiceAccount",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "pod-security",
	ResourceType: k8scol.PodType,
	Description: "Every namespace ships with a default ServiceAccount. Pods " +
		"that use it accumulate ambient RBAC over time — anything granted " +
		"to default:default leaks to every workload in the namespace. CIS " +
		"requires explicit per-workload SAs so RBAC is reviewable per pod.",
	Remediation: "Create a per-workload ServiceAccount + reference it: " +
		"`spec.serviceAccountName: <name>`. Apply automountServiceAccountToken: " +
		"false on default to surface accidental usage.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.5.18"},
		"cis-v8":   {"6.2", "6.8"},
	},
	Tags:    []string{"k8s", "pod-security", "rbac", "serviceaccount"},
	Scanner: "pods.DefaultServiceAccount",
}

func PodDefaultServiceAccount(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckPodDefaultSA.ID, Severity: CheckPodDefaultSA.Severity,
			Resource: p.Ref(), Tags: CheckPodDefaultSA.Tags,
		}
		sa, _ := p.Attributes["service_account"].(string)
		ns, _ := p.Attributes["namespace"].(string)
		switch {
		case ns == "kube-system":
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("pod %q: kube-system pods use cluster-managed SAs", podDesc(p))
		case sa == "" || sa == "default":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: uses the namespace default ServiceAccount", podDesc(p))
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: serviceAccountName=%q", podDesc(p), sa)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 12. supplementalGroups configured ---------------------------

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
	core.Register(CheckPodShareProcessNamespace, PodShareProcessNamespace)
	core.Register(CheckPodDNSPolicy, PodDNSPolicy)
	core.Register(CheckPodPriorityClass, PodPriorityClass)
	core.Register(CheckPodHostUsers, PodHostUsers)
	core.Register(CheckPodFSGroup, PodFSGroup)
	core.Register(CheckPodRunAsGroup, PodRunAsGroup)
	core.Register(CheckPodAppArmorProfile, PodAppArmorProfile)
	core.Register(CheckPodSeccompNotUnconfined, PodSeccompNotUnconfined)
	core.Register(CheckPodRuntimeClass, PodRuntimeClass)
	core.Register(CheckPodVolumeSubpath, PodVolumeSubpath)
	core.Register(CheckPodDefaultSA, PodDefaultServiceAccount)
	core.Register(CheckPodSupplementalGroups, PodSupplementalGroups)
}
