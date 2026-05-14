package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ----- Default SA token automount --------------------------------

var CheckSADefaultAutomount = core.Check{
	ID:           "k8s-sa-default-automount",
	Title:        "Default ServiceAccounts should disable token automount",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ServiceAccountType,
	Description: "Every namespace ships with a `default` ServiceAccount " +
		"that by default has automountServiceAccountToken=true. Pods " +
		"that do not opt out get the default SA's token mounted at " +
		"/var/run/secrets/... — a credential they almost certainly do " +
		"not need. Disabling automount on the default SA forces " +
		"workloads to be explicit about API access.",
	Remediation: "`kubectl patch sa default -n <ns> -p " +
		"'{\"automountServiceAccountToken\": false}'` in every " +
		"namespace. Workloads that legitimately need API access should " +
		"declare a dedicated SA with automount=true.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "service-account", "default-sa"},
	Scanner: "rbac.SADefaultAutomount",
}

func SADefaultAutomount(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, sa := range g.ByType(k8scol.ServiceAccountType) {
		if sa.Name != "default" {
			continue
		}
		mount, _ := sa.Attributes["automount_token"].(string)
		f := core.Finding{
			CheckID:  CheckSADefaultAutomount.ID,
			Severity: CheckSADefaultAutomount.Severity,
			Resource: sa.Ref(),
			Tags:     CheckSADefaultAutomount.Tags,
		}
		if mount == "false" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("default sa %q: automount=false", roleDesc(sa))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("default sa %q: automount=%s (should be false)", roleDesc(sa), mount)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Default SA used by workloads ------------------------------

var CheckSADefaultUsed = core.Check{
	ID:           "k8s-sa-default-used",
	Title:        "Pods should not run as the default ServiceAccount",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.PodType,
	Description: "Running as the namespace's default SA means inheriting " +
		"whatever bindings exist on that SA — which is often more than " +
		"the workload requires. Dedicated per-workload SAs make least-" +
		"privilege analysis tractable and let you rotate one workload's " +
		"credentials without affecting others.",
	Remediation: "Create a per-workload ServiceAccount and reference it " +
		"via `spec.serviceAccountName` in the pod template. Bind only " +
		"the specific Roles the workload needs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "rbac", "service-account"},
	Scanner: "rbac.SADefaultUsed",
}

func SADefaultUsed(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		sa, _ := p.Attributes["service_account"].(string)
		// Empty defaults to "default" per the K8s API.
		using := sa
		if using == "" {
			using = "default"
		}
		f := core.Finding{
			CheckID:  CheckSADefaultUsed.ID,
			Severity: CheckSADefaultUsed.Severity,
			Resource: p.Ref(),
			Tags:     CheckSADefaultUsed.Tags,
		}
		if using == "default" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: uses default ServiceAccount", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: uses dedicated SA %q", podDesc(p), using)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- SA orphan -------------------------------------------------

var CheckSAOrphan = core.Check{
	ID:           "k8s-sa-orphan",
	Title:        "Custom ServiceAccounts should be used by at least one pod",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ServiceAccountType,
	Description: "An unused custom ServiceAccount is dead code — it " +
		"often retains bindings from a previous workload generation. " +
		"Leftover SAs with leftover Role/ClusterRoleBindings are a " +
		"frequent privilege-escalation surface. Either delete the SA " +
		"or repoint a workload at it.",
	Remediation: "Audit with `kubectl get sa -A` cross-referenced " +
		"against `kubectl get pods -A -o jsonpath='{.items[*].spec." +
		"serviceAccountName}'`. Delete orphans after confirming no " +
		"workload reactivation is planned.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.15", "A.5.16"},
		"cis-v8":   {"6.1", "6.2"},
	},
	Tags:    []string{"k8s", "rbac", "service-account", "hygiene"},
	Scanner: "rbac.SAOrphan",
}

func SAOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	used := map[string]struct{}{}
	for _, p := range g.ByType(k8scol.PodType) {
		ns, _ := p.Attributes["namespace"].(string)
		sa, _ := p.Attributes["service_account"].(string)
		if sa == "" {
			sa = "default"
		}
		used[ns+"/"+sa] = struct{}{}
	}
	findings := []core.Finding{}
	for _, sa := range g.ByType(k8scol.ServiceAccountType) {
		// Built-ins always pass — they are managed by the cluster.
		if sa.Name == "default" || isSystemServiceAccount(sa.Name) {
			continue
		}
		ns, _ := sa.Attributes["namespace"].(string)
		_, inUse := used[ns+"/"+sa.Name]
		f := core.Finding{
			CheckID:  CheckSAOrphan.ID,
			Severity: CheckSAOrphan.Severity,
			Resource: sa.Ref(),
			Tags:     CheckSAOrphan.Tags,
		}
		if inUse {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("sa %q: used by at least one pod", roleDesc(sa))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("sa %q: not used by any pod", roleDesc(sa))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- SA image pull secrets -------------------------------------

var CheckSAImagePullSecrets = core.Check{
	ID:           "k8s-sa-imagepull-secrets-set",
	Title:        "ServiceAccounts pulling from private registries should declare imagePullSecrets",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "rbac",
	ResourceType: k8scol.ServiceAccountType,
	Description: "When a pod's image lives in a private registry, the " +
		"pull is authenticated either via the pod's imagePullSecrets " +
		"or — more commonly — via secrets attached to the pod's " +
		"ServiceAccount. A SA used by pods pulling from registries " +
		"other than docker.io or public quay/ghcr.io should have " +
		"imagePullSecrets attached.",
	Remediation: "`kubectl patch sa <name> -n <ns> -p '{\"" +
		"imagePullSecrets\": [{\"name\": \"<docker-secret>\"}]}'`. " +
		"Maintain the dockerconfigjson Secret outside the cluster (or " +
		"via external-secrets) so the value can rotate cleanly.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC8.1"},
		"iso27001": {"A.8.30"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "rbac", "service-account", "supply-chain"},
	Scanner: "rbac.SAImagePullSecrets",
}

func SAImagePullSecrets(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	// Build map: ns/sa -> []private-registry-images-pulled.
	registries := map[string]map[string]struct{}{}
	for _, p := range g.ByType(k8scol.PodType) {
		ns, _ := p.Attributes["namespace"].(string)
		sa, _ := p.Attributes["service_account"].(string)
		if sa == "" {
			sa = "default"
		}
		key := ns + "/" + sa
		containers, _ := p.Attributes["containers"].([]any)
		for _, ci := range containers {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			img, _ := c["image"].(string)
			if isPrivateRegistryImage(img) {
				if registries[key] == nil {
					registries[key] = map[string]struct{}{}
				}
				registries[key][img] = struct{}{}
			}
		}
	}

	for _, sa := range g.ByType(k8scol.ServiceAccountType) {
		ns, _ := sa.Attributes["namespace"].(string)
		key := ns + "/" + sa.Name
		usedImages, hasPrivate := registries[key]
		f := core.Finding{
			CheckID:  CheckSAImagePullSecrets.ID,
			Severity: CheckSAImagePullSecrets.Severity,
			Resource: sa.Ref(),
			Tags:     CheckSAImagePullSecrets.Tags,
		}
		if !hasPrivate {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("sa %q: no pods pulling from private registries", roleDesc(sa))
			findings = append(findings, f)
			continue
		}
		count := 0
		if c, ok := sa.Attributes["image_pull_secret_count"].(int); ok {
			count = c
		}
		if count > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("sa %q: %d imagePullSecret(s) attached (%d private image(s))", roleDesc(sa), count, len(usedImages))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("sa %q: pulls private images %v but no imagePullSecrets attached", roleDesc(sa), keysOf(usedImages))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers + init --------------------------------------------

func init() {
	core.Register(CheckSADefaultAutomount, SADefaultAutomount)
	core.Register(CheckSADefaultUsed, SADefaultUsed)
	core.Register(CheckSAOrphan, SAOrphan)
	core.Register(CheckSAImagePullSecrets, SAImagePullSecrets)
}

func isSystemServiceAccount(name string) bool {
	switch name {
	case "kube-proxy", "coredns", "kube-controller-manager", "kube-scheduler",
		"node-controller", "metrics-server", "konnectivity-agent":
		return true
	}
	return false
}

// isPrivateRegistryImage returns true when the image references a
// registry that is *not* in the well-known public set. The check is a
// heuristic — registries.example.com:5000/x clearly private, docker.io/x
// or library/x clearly public.
func isPrivateRegistryImage(image string) bool {
	// Strip digest/tag — only care about the registry portion.
	parts := splitImage(image)
	host := parts.host
	if host == "" {
		// docker.io implicit
		return false
	}
	switch host {
	case "docker.io", "registry.hub.docker.com", "quay.io",
		"ghcr.io", "registry.k8s.io", "k8s.gcr.io", "gcr.io",
		"mcr.microsoft.com", "public.ecr.aws", "registry-1.docker.io":
		return false
	}
	return true
}

type imageParts struct{ host, path, tag string }

func splitImage(image string) imageParts {
	out := imageParts{}
	// digest split
	if at := indexOf(image, '@'); at >= 0 {
		image = image[:at]
	}
	// Find first / — if before that there's a "." or ":", treat as host.
	slash := indexOf(image, '/')
	if slash > 0 {
		head := image[:slash]
		if hasAny(head, ".:") {
			out.host = head
			image = image[slash+1:]
		}
	}
	// tag
	if colon := lastIndexOf(image, ':'); colon >= 0 {
		out.tag = image[colon+1:]
		image = image[:colon]
	}
	out.path = image
	return out
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexOf(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func hasAny(s, chars string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return true
			}
		}
	}
	return false
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
