package kubectl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func init() {
	register("k8s-pod-run-as-non-root",
		[]string{"k8s-pod-run-as-non-root"},
		renderRunAsNonRoot)
	register("k8s-pod-allow-privilege-escalation",
		[]string{"k8s-pod-allow-privilege-escalation"},
		renderAllowPrivilegeEscalation)
	register("k8s-pod-readonly-root-fs",
		[]string{"k8s-pod-readonly-root-fs"},
		renderReadOnlyRootFS)
	register("k8s-pod-capabilities-drop-all",
		[]string{"k8s-pod-capabilities-drop-all", "k8s-pod-dangerous-capabilities"},
		renderCapabilitiesDropAll)
	register("k8s-pod-seccomp-profile",
		[]string{"k8s-pod-seccomp-profile"},
		renderSeccompProfile)
	register("k8s-pod-privileged",
		[]string{"k8s-pod-privileged"},
		renderPrivileged)
	register("k8s-pod-host-namespaces",
		[]string{"k8s-pod-host-network", "k8s-pod-host-pid", "k8s-pod-host-ipc"},
		renderHostNamespaces)
	register("k8s-pod-host-path-volume",
		[]string{"k8s-pod-host-path-volume"},
		renderHostPathVolume)
	register("k8s-pod-automount-sa-token",
		[]string{"k8s-pod-automount-sa-token", "k8s-sa-default-automount"},
		renderAutomountSAToken)
	register("k8s-pod-image-tag-latest",
		[]string{"k8s-pod-image-tag-latest"},
		renderImageTagLatest)
	register("k8s-pod-image-pull-policy",
		[]string{"k8s-pod-image-pull-policy"},
		renderImagePullPolicy)
}

func renderRunAsNonRoot(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532`
	cmd := kubectlPatch(kind, ns, name, patch)

	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532       # nonroot UID in distroless images
        runAsGroup: 65532
        fsGroup: 65532
      # ... rest of existing spec
`, kind, name, ns)

	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl get %s %s -n %s -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}'", lowerKind(kind), render.ShellQuote(name), render.ShellQuote(ns)),
		Notes:      "Containers built on distroless or Alpine commonly accept UID 65532. Custom images that hard-code paths writable only by root (e.g. /var/run pid files) need either readOnlyRootFilesystem=false + writable volumes, or a USER directive in the Dockerfile.",
		Refs: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	}, nil
}

func renderAllowPrivilegeEscalation(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        securityContext:
          allowPrivilegeEscalation: false`
	cmd := kubectlPatch(kind, ns, name, patch)
	manifest := fmt.Sprintf(`# Set on each container in %s/%s/%s:
securityContext:
  allowPrivilegeEscalation: false
`, kind, ns, name)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		Notes:      "Required for PodSecurity 'restricted'. Blocks setuid escalation inside the container — most non-init applications never need this and the few that do (e.g. ping in Alpine) are better served by CAP_NET_RAW on the dropped-capabilities allowlist.",
	}, nil
}

func renderReadOnlyRootFS(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}`
	cmd := kubectlPatch(kind, ns, name, patch)
	manifest := patch + "\n"
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		Notes:      "Most apps write to /tmp; mount an emptyDir there as shown. If the app also writes to /var/log or similar, add additional emptyDir volumes. Java apps usually need /tmp + their cache dir.",
	}, nil
}

func renderCapabilitiesDropAll(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        securityContext:
          capabilities:
            drop:
            - ALL`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Drops every Linux capability. Apps that bind to ports < 1024 (rare for modern apps; common for legacy nginx/apache) need CAP_NET_BIND_SERVICE in capabilities.add — better: switch to port 8080 + NodePort/LB.",
	}, nil
}

func renderSeccompProfile(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "RuntimeDefault uses Docker's / containerd's default seccomp profile — blocks ~44 syscalls used in container escapes but never by normal applications. Required for PodSecurity 'restricted'.",
	}, nil
}

func renderPrivileged(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        securityContext:
          privileged: false`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Privileged: true is required only by storage drivers, eBPF agents, and similar host-level workloads. App containers should NEVER be privileged. If your workload needs specific capabilities (CAP_NET_ADMIN, CAP_SYS_PTRACE), add them explicitly to securityContext.capabilities.add rather than enabling privileged.",
	}, nil
}

func renderHostNamespaces(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      hostNetwork: false
      hostPID: false
      hostIPC: false`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Removes host namespace sharing. Host-network is sometimes required for CNIs, kube-proxy, ingress controllers in DaemonSets — verify this isn't one of those before applying. hostPID + hostIPC are almost never needed.",
	}, nil
}

func renderHostPathVolume(f compliancekit.Finding) (remediate.Snippet, error) {
	_, _, name := workloadFromResource(f)
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation — replace hostPath with a managed volume.\n",
		Notes: fmt.Sprintf(
			"Pod %q uses hostPath. Replacement depends on what it's accessing: 1) configuration files → ConfigMap or Secret; 2) shared scratch space → emptyDir; 3) persistent data → PersistentVolumeClaim with a CSI driver. hostPath leaks the node filesystem into the pod and breaks node portability — there is no in-place fix.",
			name),
		Refs: []string{
			"https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
		},
	}, nil
}

func renderAutomountSAToken(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      automountServiceAccountToken: false`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Disables the kube-apiserver client token from being mounted. Apps that legitimately call the K8s API (operators, in-cluster Helm releases, leader-election libraries) need this set to true and a dedicated ServiceAccount with the correct minimum RBAC — see k8s-rbac-* findings.",
	}, nil
}

func renderImageTagLatest(f compliancekit.Finding) (remediate.Snippet, error) {
	_, _, name := workloadFromResource(f)
	return remediate.Snippet{
		Risk:       remediate.RiskManual,
		Idempotent: false,
		Content:    "# Manual remediation — pin every container to an immutable tag or digest.\n",
		Notes: fmt.Sprintf(
			"Workload %q uses :latest or no tag. Pin to a versioned tag (myimg:v1.2.3) or, ideally, a digest (myimg@sha256:abc...). Pinning to a digest is the SLSA-compliant practice — tags can be repointed but digests cannot. Update your CI to write the digest into the manifest as part of the deploy.",
			name),
		Refs: []string{
			"https://kubernetes.io/docs/concepts/containers/images/#image-names",
		},
	}, nil
}

func renderImagePullPolicy(f compliancekit.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        imagePullPolicy: IfNotPresent`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "IfNotPresent is the right default for digest-pinned or version-pinned images. Use 'Always' ONLY when you also use :latest (which compliancekit also flags). For internal registries with strict pull rate limits, IfNotPresent saves pulls.",
	}, nil
}

// lowerKind is a tiny helper so kubectl get/describe accept the
// resource type — kubectl is case-insensitive but lowercase reads
// canonically in runbooks.
func lowerKind(k string) string {
	if k == "" {
		return "pod"
	}
	return fmt.Sprintf("%s%s", string(k[0]|0x20), k[1:])
}
