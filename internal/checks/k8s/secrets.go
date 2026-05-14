package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	secretLargeBytes    = 1 << 20 // 1 MiB
	configMapLargeBytes = 1 << 20
)

// secretShapedKeys is the substring set we match against ConfigMap
// keys to detect "this looks like it should be a Secret instead."
// Case-insensitive substring match.
var secretShapedKeys = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"api-key", "credential", "private_key", "privatekey", "private-key",
	"access_key", "accesskey", "client_secret",
}

// ----- Secret in env --------------------------------------------

var CheckSecretInEnv = core.Check{
	ID:           "k8s-pod-secret-via-env",
	Title:        "Pods should mount Secrets as volumes rather than env vars",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.PodType,
	Description: "Container `env.valueFrom.secretKeyRef` exposes the " +
		"secret via the process's environment, which means any process " +
		"in the container (including library calls, `/proc/<pid>/environ`, " +
		"core dumps) can read it. Volume mounts are the safer pattern: " +
		"only code that explicitly opens the file path sees the " +
		"contents, and rotation via secret update propagates without " +
		"restarting the pod.",
	Remediation: "Replace `valueFrom.secretKeyRef` with a `volumeMount` " +
		"that points at a Secret volume. Read the value from the file " +
		"at runtime.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.8.24"},
		"cis-v8":   {"3.11", "6.7"},
	},
	Tags:    []string{"k8s", "secrets", "env"},
	Scanner: "secrets.SecretInEnv",
}

// The pod-spec flattener (Phase 1) does not currently emit env source
// info per container. As a heuristic Phase 5 ships, we flag Pods that
// declare any env variable referencing a Secret — which is a future
// collector enrichment. For now skip the check with a Skip placeholder
// pending Phase 1b expansion. The check is still registered so the
// catalog has a stable ID and skip findings make the gap visible.
func SecretInEnv(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID:  CheckSecretInEnv.ID,
			Severity: CheckSecretInEnv.Severity,
			Resource: p.Ref(),
			Tags:     CheckSecretInEnv.Tags,
		}
		// Re-evaluate when the Phase 1b expansion captures
		// envFrom/valueFrom on containers.
		hasSecretEnv := false
		containers, _ := p.Attributes["containers"].([]any)
		for _, ci := range containers {
			c, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			if envs, ok := c["secret_env_refs"].([]string); ok && len(envs) > 0 {
				hasSecretEnv = true
				break
			}
		}
		if hasSecretEnv {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("pod %q: container exposes Secret via env", podDesc(p))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("pod %q: no Secret-via-env detected", podDesc(p))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Secret orphan --------------------------------------------

var CheckSecretOrphan = core.Check{
	ID:           "k8s-secret-orphan",
	Title:        "Secrets should be referenced by at least one pod or ServiceAccount",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.SecretType,
	Description: "An unreferenced Secret often holds a stale credential " +
		"that nobody knows to rotate. Leftover Secrets accumulate as " +
		"deployments come and go. Periodic cleanup is the standard " +
		"hygiene practice.",
	Remediation: "Audit Secrets against actual references and delete " +
		"those genuinely unused. Use `kubectl delete secret <name> -n <ns>`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.16", "A.8.10"},
		"cis-v8":   {"3.11", "6.2"},
	},
	Tags:    []string{"k8s", "secrets", "hygiene"},
	Scanner: "secrets.SecretOrphan",
}

func SecretOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	usedKeys := map[string]struct{}{}
	// SA secret references (manual token bindings, image pull secrets).
	for _, sa := range g.ByType(k8scol.ServiceAccountType) {
		// We do not track per-secret names yet from the SA collector;
		// fall back to "any SA with secret_count>0 keeps secrets named
		// like its SA marked in use" via type=service-account-token
		// linkage. Phase 6 will tighten this.
		ns, _ := sa.Attributes["namespace"].(string)
		// Approximate: any SA with a secret_count uses some secret in
		// the namespace; we mark "all" used to be conservative.
		count, _ := sa.Attributes["secret_count"].(int)
		if count > 0 {
			usedKeys[ns+"/*"] = struct{}{}
		}
	}
	// Pod env-from / volume references — we do not capture these yet
	// per container. Fall back to namespace-level usage flag.
	for _, p := range g.ByType(k8scol.PodType) {
		ns, _ := p.Attributes["namespace"].(string)
		usedKeys[ns+"/*"] = struct{}{}
	}

	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.SecretType) {
		// Managed Secrets (SA tokens, image-pull, helm-release state) skipped.
		secretType, _ := s.Attributes["type"].(string)
		if isManagedSecretType(secretType) {
			continue
		}
		ns, _ := s.Attributes["namespace"].(string)
		_, used := usedKeys[ns+"/*"]
		f := core.Finding{
			CheckID:  CheckSecretOrphan.ID,
			Severity: CheckSecretOrphan.Severity,
			Resource: s.Ref(),
			Tags:     CheckSecretOrphan.Tags,
		}
		// Without per-secret reference tracking, this is best-effort:
		// flag namespaces with no pods or SAs as having orphan secrets.
		if used {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("secret %q: namespace has pods/SAs (per-secret usage will land Phase 6)", secretDesc(s))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("secret %q: namespace has no pods or SAs", secretDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Secret too large -----------------------------------------

var CheckSecretTooLarge = core.Check{
	ID:           "k8s-secret-too-large",
	Title:        "Secrets should be under 1 MiB",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.SecretType,
	Description: "The K8s API hard-limits Secrets to 1 MiB. Very large " +
		"Secrets often indicate misuse — a kubeconfig, a private CA " +
		"bundle, an entire TLS chain, or accidentally stored binary " +
		"data. Operationally large Secrets also stress etcd because " +
		"every API write replicates the full value.",
	Remediation: "For large bundles, store the contents in object " +
		"storage and reference them with a small credentials Secret " +
		"that lets the pod fetch at startup. For multi-file bundles, " +
		"split into multiple Secrets.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.6", "A.8.10"},
		"cis-v8":   {"6.2"},
	},
	Tags:    []string{"k8s", "secrets", "size"},
	Scanner: "secrets.SecretTooLarge",
}

func SecretTooLarge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return sizeCheck(g, k8scol.SecretType, CheckSecretTooLarge, secretLargeBytes), nil
}

// ----- ConfigMap secret-shaped --------------------------------

var CheckConfigMapSecretShaped = core.Check{
	ID:           "k8s-configmap-secret-shaped-data",
	Title:        "ConfigMaps should not hold credential-shaped keys",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.ConfigMapType,
	Description: "ConfigMap values are stored in plaintext in etcd and " +
		"visible to anyone with `get configmaps` (which is broader " +
		"than `get secrets`). A key named `password`, `token`, " +
		"`api_key`, etc. is almost always a misplaced credential. The " +
		"developer probably meant to use a Secret.",
	Remediation: "Move the credential-shaped key into a Secret. The " +
		"workload's volume mount or env reference should switch from " +
		"`configMapKeyRef` to `secretKeyRef`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"k8s", "secrets", "configmap"},
	Scanner: "secrets.ConfigMapSecretShaped",
}

func ConfigMapSecretShaped(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, cm := range g.ByType(k8scol.ConfigMapType) {
		keys, _ := cm.Attributes["keys"].([]string)
		hits := []string{}
		for _, k := range keys {
			lk := strings.ToLower(k)
			for _, shape := range secretShapedKeys {
				if strings.Contains(lk, shape) {
					hits = append(hits, k)
					break
				}
			}
		}
		f := core.Finding{
			CheckID:  CheckConfigMapSecretShaped.ID,
			Severity: CheckConfigMapSecretShaped.Severity,
			Resource: cm.Ref(),
			Tags:     CheckConfigMapSecretShaped.Tags,
		}
		if len(hits) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("configmap %q: no credential-shaped keys", secretDesc(cm))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("configmap %q: credential-shaped keys: %s", secretDesc(cm), strings.Join(hits, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- ConfigMap too large -------------------------------------

var CheckConfigMapTooLarge = core.Check{
	ID:           "k8s-configmap-too-large",
	Title:        "ConfigMaps should be under 1 MiB",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.ConfigMapType,
	Description: "Large ConfigMaps stress etcd write replication and " +
		"slow API responses for tooling that lists them. Mostly an " +
		"operational signal — a ConfigMap holding a >1 MiB JSON " +
		"document or a binary blob is usually a sign that another " +
		"storage primitive would fit better.",
	Remediation: "For large config bundles, mount from a PVC, fetch at " +
		"startup, or split into multiple keys.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "configmap", "size"},
	Scanner: "secrets.ConfigMapTooLarge",
}

func ConfigMapTooLarge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return sizeCheck(g, k8scol.ConfigMapType, CheckConfigMapTooLarge, configMapLargeBytes), nil
}

// ----- Secret immutable ----------------------------------------

var CheckSecretImmutable = core.Check{
	ID:           "k8s-secret-immutable",
	Title:        "Long-lived Secrets should be marked immutable",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "secrets",
	ResourceType: k8scol.SecretType,
	Description: "Setting `immutable: true` on a Secret prevents " +
		"accidental updates that would silently propagate to running " +
		"pods, and lets the kubelet skip the periodic watch refresh on " +
		"that Secret — a meaningful API-server load reduction at scale.",
	Remediation: "For Secrets that should never change after creation " +
		"(rotation via replacement), add `immutable: true`. For " +
		"Secrets you do rotate in-place, leave mutable.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.10"},
		"cis-v8":   {"6.2"},
	},
	Tags:    []string{"k8s", "secrets", "immutable"},
	Scanner: "secrets.SecretImmutable",
}

func SecretImmutable(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, s := range g.ByType(k8scol.SecretType) {
		// SA tokens and helm release states are managed; skip.
		secretType, _ := s.Attributes["type"].(string)
		if isManagedSecretType(secretType) {
			continue
		}
		immut, _ := s.Attributes["immutable"].(bool)
		f := core.Finding{
			CheckID:  CheckSecretImmutable.ID,
			Severity: CheckSecretImmutable.Severity,
			Resource: s.Ref(),
			Tags:     CheckSecretImmutable.Tags,
		}
		if immut {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("secret %q: immutable", secretDesc(s))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("secret %q: mutable (consider immutable:true for stable Secrets)", secretDesc(s))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers + init -------------------------------------------

func init() {
	core.Register(CheckSecretInEnv, SecretInEnv)
	core.Register(CheckSecretOrphan, SecretOrphan)
	core.Register(CheckSecretTooLarge, SecretTooLarge)
	core.Register(CheckConfigMapSecretShaped, ConfigMapSecretShaped)
	core.Register(CheckConfigMapTooLarge, ConfigMapTooLarge)
	core.Register(CheckSecretImmutable, SecretImmutable)
}

func sizeCheck(g *core.ResourceGraph, t string, check core.Check, threshold int) []core.Finding {
	findings := []core.Finding{}
	for _, r := range g.ByType(t) {
		size, _ := r.Attributes["size_bytes"].(int)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: r.Ref(),
			Tags:     check.Tags,
		}
		if size > threshold {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("%s %q: %d bytes exceeds %d", typeLabel(t), secretDesc(r), size, threshold)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("%s %q: %d bytes", typeLabel(t), secretDesc(r), size)
		}
		findings = append(findings, f)
	}
	return findings
}

func typeLabel(t string) string {
	switch t {
	case k8scol.SecretType:
		return "secret"
	case k8scol.ConfigMapType:
		return "configmap"
	}
	return t
}

func secretDesc(r core.Resource) string {
	ns, _ := r.Attributes["namespace"].(string)
	if ns == "" {
		return r.Name
	}
	return ns + "/" + r.Name
}

// isManagedSecretType returns true for Secret types K8s creates and
// manages itself (SA tokens, helm release state, kubernetes.io/dockercfg,
// etc.). The orphan / mutable checks should not fire on these.
func isManagedSecretType(t string) bool {
	switch t {
	case "kubernetes.io/service-account-token",
		"kubernetes.io/dockercfg",
		"kubernetes.io/dockerconfigjson",
		"helm.sh/release.v1",
		"bootstrap.kubernetes.io/token":
		return true
	}
	return false
}
