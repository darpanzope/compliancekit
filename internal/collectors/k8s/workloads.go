package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/darpanzope/compliancekit/internal/collectors/cloudcommon"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// collectWorkloads emits k8s.pod resources for every Pod visible in
// the scope. Phase 2 expands to Deployments / StatefulSets / DaemonSets
// / Jobs / CronJobs; Phase 1 ships Pods only since the Pod Security
// checks all target the runtime Pod surface.
func (c *Collector) collectWorkloads(ctx context.Context, scope *ContextScope) ([]compliancekit.Resource, error) {
	pods, err := listPods(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	out := make([]compliancekit.Resource, 0, len(pods))
	for i := range pods {
		out = append(out, c.podResource(scope, &pods[i]))
	}
	return out, nil
}

// listPods returns every Pod visible in the scope. When scope.Namespaces
// is empty it issues a single all-namespaces list; otherwise it issues
// one list per requested namespace.
//
// ExcludeNamespaces filters the result client-side regardless of which
// branch ran.
func listPods(ctx context.Context, scope *ContextScope) ([]corev1.Pod, error) {
	if len(scope.Namespaces) == 0 {
		raw, err := scope.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return filterPodsByExclude(raw.Items, scope.ExcludeNamespaces), nil
	}
	all := make([]corev1.Pod, 0)
	for _, ns := range scope.Namespaces {
		raw, err := scope.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		all = append(all, filterPodsByExclude(raw.Items, scope.ExcludeNamespaces)...)
	}
	return all, nil
}

func filterPodsByExclude(pods []corev1.Pod, exclude []string) []corev1.Pod {
	if len(exclude) == 0 {
		return pods
	}
	out := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if !contains(exclude, pods[i].Namespace) {
			out = append(out, pods[i])
		}
	}
	return out
}

// podResource flattens the bits of pod.Spec the Pod Security checks
// inspect into a compliancekit.Resource attribute map. The flattening is
// deliberate — keeping check code free of client-go imports means the
// catalog stays loadable from a binary that never touches the K8s API.
func (c *Collector) podResource(scope *ContextScope, pod *corev1.Pod) compliancekit.Resource {
	attrs := map[string]any{
		"namespace":          pod.Namespace,
		"service_account":    pod.Spec.ServiceAccountName,
		"host_network":       pod.Spec.HostNetwork,
		"host_pid":           pod.Spec.HostPID,
		"host_ipc":           pod.Spec.HostIPC,
		"automount_sa_token": automountValue(pod.Spec.AutomountServiceAccountToken),
		"host_path_volumes":  collectHostPathVolumes(pod.Spec.Volumes),
		"pod_security":       flattenPodSecurityContext(pod.Spec.SecurityContext),
		"containers":         collectContainers(pod),
		"owner_kind":         firstOwnerKind(pod.OwnerReferences),
		"owner_name":         firstOwnerName(pod.OwnerReferences),
		// v0.21 phase 1 — pod-security deepening surface.
		"share_process_namespace": boolPtrOrNil(pod.Spec.ShareProcessNamespace),
		"dns_policy":              string(pod.Spec.DNSPolicy),
		"priority_class_name":     pod.Spec.PriorityClassName,
		"runtime_class_name":      stringPtrOrEmpty(pod.Spec.RuntimeClassName),
		"host_users":              boolPtrOrNil(pod.Spec.HostUsers),
		"apparmor_profile":        apparmorProfileFromAnnotations(pod.Annotations),
		"volume_subpath_mounts":   collectVolumeSubpathMounts(pod),
		// v0.21 phase 2 — workload reliability surface.
		"termination_grace_period":    int64PtrOrZero(pod.Spec.TerminationGracePeriodSeconds),
		"topology_spread_constraints": len(pod.Spec.TopologySpreadConstraints),
		"init_container_count":        len(pod.Spec.InitContainers),
	}
	r := compliancekit.Resource{
		ID:         fmt.Sprintf("%s.%s.%s.%s", PodType, scope.Name, pod.Namespace, pod.Name),
		Type:       PodType,
		Name:       pod.Name,
		Provider:   providerName,
		Attributes: attrs,
	}
	cloudcommon.Stamp(&r, cloudcommon.ResourceCoord{
		AccountID: scope.AccountID(),
		Region:    scope.Region(),
	})
	return r
}

func collectContainers(pod *corev1.Pod) []any {
	out := make([]any, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	for i := range pod.Spec.InitContainers {
		out = append(out, containerMap(&pod.Spec.InitContainers[i], "init"))
	}
	for i := range pod.Spec.Containers {
		out = append(out, containerMap(&pod.Spec.Containers[i], "container"))
	}
	return out
}

func containerMap(c *corev1.Container, kind string) map[string]any {
	sc := c.SecurityContext
	return map[string]any{
		"name":                  c.Name,
		"kind":                  kind,
		"image":                 c.Image,
		"image_tag":             imageTag(c.Image),
		"image_pull_policy":     string(c.ImagePullPolicy),
		"privileged":            boolFromSC(sc, func(s *corev1.SecurityContext) *bool { return s.Privileged }),
		"allow_priv_escalation": boolFromSC(sc, func(s *corev1.SecurityContext) *bool { return s.AllowPrivilegeEscalation }),
		"run_as_non_root":       boolFromSC(sc, func(s *corev1.SecurityContext) *bool { return s.RunAsNonRoot }),
		"run_as_user":           runAsUserFromSC(sc),
		"read_only_root_fs":     boolFromSC(sc, func(s *corev1.SecurityContext) *bool { return s.ReadOnlyRootFilesystem }),
		"capabilities_add":      capabilitiesList(sc, true),
		"capabilities_drop":     capabilitiesList(sc, false),
		"seccomp_type":          seccompTypeFromContainerSC(sc),
		"has_cpu_limit":         !c.Resources.Limits.Cpu().IsZero(),
		"has_memory_limit":      !c.Resources.Limits.Memory().IsZero(),
		"has_cpu_request":       !c.Resources.Requests.Cpu().IsZero(),
		"has_memory_request":    !c.Resources.Requests.Memory().IsZero(),
		"has_liveness_probe":    c.LivenessProbe != nil,
		"host_ports":            hostPortsList(c.Ports),
		// v0.21 phase 2 — reliability + supply-chain surface.
		"has_readiness_probe":         c.ReadinessProbe != nil,
		"has_startup_probe":           c.StartupProbe != nil,
		"has_ephemeral_storage_limit": !c.Resources.Limits.StorageEphemeral().IsZero(),
		"image_digest_pinned":         isImageDigestPinned(c.Image),
	}
}

// int64PtrOrZero returns the dereferenced *int64 or 0 when nil — used
// for TerminationGracePeriodSeconds where k8s emits a default of 30
// when unset (but we want the raw field for "operator explicitly set
// this" semantics on the v0.21 reliability checks).
func int64PtrOrZero(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

// isImageDigestPinned returns true when the image reference contains a
// "@sha256:" digest suffix. Pinned digests defeat the tag-mutation
// supply-chain attack (where a registry owner pushes a malicious image
// at an existing tag). Tags alone — including :latest, semver tags,
// and date tags — are mutable.
func isImageDigestPinned(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func collectHostPathVolumes(vols []corev1.Volume) []string {
	out := []string{}
	for i := range vols {
		if vols[i].HostPath != nil {
			out = append(out, vols[i].Name+":"+vols[i].HostPath.Path)
		}
	}
	return out
}

func flattenPodSecurityContext(sc *corev1.PodSecurityContext) map[string]any {
	if sc == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if sc.RunAsNonRoot != nil {
		out["run_as_non_root"] = *sc.RunAsNonRoot
	}
	if sc.RunAsUser != nil {
		out["run_as_user"] = *sc.RunAsUser
	}
	if sc.SeccompProfile != nil {
		out["seccomp_type"] = string(sc.SeccompProfile.Type)
	}
	// v0.21 phase 1 — fs/run-as-group + supplemental groups for
	// the new pod-security deepening checks.
	if sc.RunAsGroup != nil {
		out["run_as_group"] = *sc.RunAsGroup
	}
	if sc.FSGroup != nil {
		out["fs_group"] = *sc.FSGroup
	}
	if len(sc.SupplementalGroups) > 0 {
		groups := make([]int64, len(sc.SupplementalGroups))
		copy(groups, sc.SupplementalGroups)
		out["supplemental_groups"] = groups
	}
	return out
}

// boolPtrOrNil returns the dereferenced bool or nil when ptr is nil so
// downstream checks can distinguish "explicitly false" from "unset"
// (k8s defaults vary: ShareProcessNamespace nil ⇒ false, HostUsers nil
// ⇒ true on k8s ≥ 1.30).
func boolPtrOrNil(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// stringPtrOrEmpty returns the dereferenced string or "" when the
// caller didn't set RuntimeClassName.
func stringPtrOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// apparmorProfileFromAnnotations extracts the per-container AppArmor
// profile annotations (`container.apparmor.security.beta.kubernetes.io/<name>`)
// + flattens to "container=profile" pairs. Returns empty slice on
// k8s ≥ 1.30 hosts that have migrated to securityContext.appArmorProfile
// (left to per-container surface).
func apparmorProfileFromAnnotations(ann map[string]string) []string {
	if len(ann) == 0 {
		return nil
	}
	const prefix = "container.apparmor.security.beta.kubernetes.io/"
	out := []string{}
	for k, v := range ann {
		if strings.HasPrefix(k, prefix) {
			out = append(out, strings.TrimPrefix(k, prefix)+"="+v)
		}
	}
	return out
}

// collectVolumeSubpathMounts walks every container's volumeMounts +
// returns "container/volume:subPath" entries. subPath is a documented
// symlink-attack vector (CVE-2017-1002101 family) when the volume is
// emptyDir or a hostPath; auditors want the list surfaced.
func collectVolumeSubpathMounts(pod *corev1.Pod) []string {
	out := []string{}
	walk := func(cs []corev1.Container) {
		for _, c := range cs {
			for _, vm := range c.VolumeMounts {
				if vm.SubPath != "" || vm.SubPathExpr != "" {
					sp := vm.SubPath
					if sp == "" {
						sp = vm.SubPathExpr
					}
					out = append(out, c.Name+"/"+vm.Name+":"+sp)
				}
			}
		}
	}
	walk(pod.Spec.InitContainers)
	walk(pod.Spec.Containers)
	return out
}

func boolFromSC(sc *corev1.SecurityContext, pick func(*corev1.SecurityContext) *bool) any {
	if sc == nil {
		return nil
	}
	v := pick(sc)
	if v == nil {
		return nil
	}
	return *v
}

func runAsUserFromSC(sc *corev1.SecurityContext) any {
	if sc == nil || sc.RunAsUser == nil {
		return nil
	}
	return *sc.RunAsUser
}

func capabilitiesList(sc *corev1.SecurityContext, addList bool) []string {
	out := []string{}
	if sc == nil || sc.Capabilities == nil {
		return out
	}
	var src []corev1.Capability
	if addList {
		src = sc.Capabilities.Add
	} else {
		src = sc.Capabilities.Drop
	}
	for _, cap := range src {
		out = append(out, string(cap))
	}
	return out
}

func seccompTypeFromContainerSC(sc *corev1.SecurityContext) string {
	if sc == nil || sc.SeccompProfile == nil {
		return ""
	}
	return string(sc.SeccompProfile.Type)
}

func hostPortsList(ports []corev1.ContainerPort) []int {
	out := []int{}
	for _, p := range ports {
		if p.HostPort != 0 {
			out = append(out, int(p.HostPort))
		}
	}
	return out
}

func automountValue(b *bool) string {
	if b == nil {
		return "unset"
	}
	if *b {
		return "true"
	}
	return "false"
}

func firstOwnerKind(refs []metav1.OwnerReference) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0].Kind
}

func firstOwnerName(refs []metav1.OwnerReference) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0].Name
}

// imageTag returns the tag portion of a container image string. Returns
// "latest" when no tag is present (the K8s default). Digest-pinned
// images (image@sha256:...) return the digest as the "tag" so the
// :latest check passes them.
func imageTag(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		return image[i+1:]
	}
	// Strip registry/repo prefix at the last "/", then look for ":".
	slash := strings.LastIndex(image, "/")
	rest := image
	if slash >= 0 {
		rest = image[slash+1:]
	}
	if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		return rest[colon+1:]
	}
	return "latest"
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}
