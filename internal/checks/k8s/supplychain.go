package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.21 phase 5 — supply chain. 10 checks covering the dimensions
// CIS Kubernetes Benchmark §5.x + the SLSA / cosign / in-toto
// ecosystem call out as build-time/registry-time risk. Several
// surface as manual-verify because the verification path requires
// out-of-band tooling (cosign binary, registry catalog walk) that
// the compliancekit binary deliberately doesn't carry.

// ----- 1. image tag mutable (latest / floating tags) ---------------

var CheckImageMutableTag = core.Check{
	ID:           "k8s-pod-image-tag-not-mutable",
	Title:        "Container images should not use mutable tags (latest, master, develop)",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Tags like :latest, :master, :develop, :main are " +
		"conventionally floating — a new push to the registry replaces " +
		"the image any prior pull resolved. Combined with " +
		"imagePullPolicy: IfNotPresent (the default for non-:latest " +
		"tags) the production pod can stay on an old version while " +
		"new pods pulled fresh content. Combined with " +
		"imagePullPolicy: Always, every pod restart is a supply-chain " +
		"surface. Pinning the digest (k8s-pod-image-digest-pinned) is " +
		"strictly stronger; this check catches the lower bar.",
	Remediation: "Replace mutable tags with semver tags (`:v1.2.3`) or " +
		"sha256 digests (`@sha256:...`). Use Renovate / dependabot to " +
		"keep the references current.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.6", "7.1"},
	},
	Tags:    []string{"k8s", "supply-chain", "image"},
	Scanner: "supplychain.ImageMutableTag",
}

var mutableTagNames = map[string]bool{
	"latest": true, "master": true, "main": true, "develop": true,
	"dev": true, "stable": true, "edge": true, "nightly": true,
}

func ImageMutableTag(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			tag, _ := c["image_tag"].(string)
			return mutableTagNames[strings.ToLower(strings.TrimSpace(tag))]
		})
		findings = append(findings, podFinding(CheckImageMutableTag, p, bad,
			"images with mutable tags (latest/master/develop): %s",
			"no mutable-tag images"))
	}
	return findings, nil
}

// ----- 2. image tag empty -----------------------------------------

var CheckImageEmptyTag = core.Check{
	ID:           "k8s-pod-image-tag-not-empty",
	Title:        "Container images must specify an explicit tag (no implicit :latest)",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "An image reference without a tag (`nginx` rather than " +
		"`nginx:1.25.3`) implicitly resolves to `:latest`. The audit " +
		"trail then doesn't even show that latest was selected — operators " +
		"often miss that no-tag means mutable-pull. Fail-fast at " +
		"manifest review beats production discovery.",
	Remediation: "Always pin a tag in the image reference. Combine with " +
		"digest pinning (k8s-pod-image-digest-pinned) for the strongest " +
		"supply-chain posture.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "image"},
	Scanner: "supplychain.ImageEmptyTag",
}

func ImageEmptyTag(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			tag, _ := c["image_tag"].(string)
			return strings.TrimSpace(tag) == ""
		})
		findings = append(findings, podFinding(CheckImageEmptyTag, p, bad,
			"images with no explicit tag (implicit :latest): %s",
			"all images have explicit tags"))
	}
	return findings, nil
}

// ----- 3. image from trusted registry (manual-verify allowlist) ---

var CheckImageTrustedRegistry = core.Check{
	ID:           "k8s-pod-image-from-trusted-registry",
	Title:        "Container images should be pulled only from allow-listed registries",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Pulling from arbitrary public registries (Docker Hub, " +
		"quay.io, ghcr.io of unverified orgs) opens supply-chain risk. " +
		"Enterprise practice is to mirror approved upstream images into " +
		"a registry the org controls + admission-block pulls from " +
		"anywhere else. Manual-verify since the trusted-registry list " +
		"varies per org (no universal default).",
	Remediation: "Implement registry-allowlist at admission via Gatekeeper " +
		"ConstraintTemplate or Kyverno ClusterPolicy. Mirror upstream " +
		"images via `crane copy` or a pull-through cache.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"7.3", "16.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "registry", "manual-verify"},
	Scanner: "supplychain.ImageTrustedRegistry",
}

func ImageTrustedRegistry(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		regs := imageRegistries(p)
		f := core.Finding{
			CheckID: CheckImageTrustedRegistry.ID, Severity: CheckImageTrustedRegistry.Severity,
			Resource: p.Ref(), Tags: CheckImageTrustedRegistry.Tags,
			Status:  core.StatusError,
			Message: fmt.Sprintf("pod %q: audit registry origins against your allowlist: %s", podDesc(p), strings.Join(regs, ", ")),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. cosign signature verified (manual-verify) ----------------

var CheckImageCosignSignature = core.Check{
	ID:           "k8s-pod-image-cosign-signature-verified",
	Title:        "Container images should be cosign-verified at admission",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Cosign-signed images carry a registry-side signature " +
		"verifiable against a public key (or keyless via Sigstore). " +
		"Pairing the signature with admission-time verification " +
		"(policy-controller, kyverno-verify-images, ratify) blocks any " +
		"image whose signature isn't valid for the org's signing key. " +
		"Manual-verify since the verification flow lives in admission " +
		"webhooks, not in pod spec.",
	Remediation: "Install one of:\n  - sigstore policy-controller " +
		"(https://docs.sigstore.dev/policy-controller/overview/)\n  - " +
		"Kyverno verify-images policy " +
		"(https://kyverno.io/policies/#verify-image)\n  - Ratify " +
		"(https://ratify.dev/).\nConfigure with the public key of your " +
		"build signer + an allow-list of subjects.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.6", "16.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "cosign", "sigstore", "manual-verify"},
	Scanner: "supplychain.ImageCosignSignature",
}

func ImageCosignSignature(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckImageCosignSignature,
		"audit whether an admission-side cosign verifier is installed: `kubectl get clusterpolicy,validatingwebhookconfiguration | grep -iE 'kyverno|policy-controller|ratify'`")
}

// ----- 5. in-toto attestation present (manual-verify) --------------

var CheckImageAttestation = core.Check{
	ID:           "k8s-pod-image-attestation-required",
	Title:        "Container images should ship in-toto SLSA attestations",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "in-toto attestations (SLSA build provenance, vulnerability " +
		"scan results, SBOMs) live alongside the image in the registry. " +
		"Admission-time verification against attestation policies " +
		"(min SLSA level 3, scan-results-passing) closes the build/" +
		"deploy gap. Manual-verify — the surface lives in admission " +
		"controllers + registry attachments, not pod spec.",
	Remediation: "Use cosign attest + cosign verify-attestation in " +
		"admission. SLSA build provenance via GitHub Actions / " +
		"slsa-github-generator; SBOM via syft + cosign attest --type=spdx.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7", "CC7.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"7.1", "16.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "slsa", "manual-verify"},
	Scanner: "supplychain.ImageAttestation",
}

func ImageAttestation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckImageAttestation,
		"audit whether admission verifies SLSA / in-toto attestations: `cosign verify-attestation --type=slsaprovenance --certificate-identity=... <image>`")
}

// ----- 6. image pull secret (private-registry usage) --------------

var CheckImagePullSecretPresent = core.Check{
	ID:           "k8s-pod-image-pull-secret-set",
	Title:        "Pods pulling from private registries should reference an imagePullSecret",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Private registry pulls without an imagePullSecret " +
		"fall back to the kubelet's node-level credentials (ECR / GCR / " +
		"ACR via cloud IAM). Sometimes that's intentional (workload " +
		"identity); often it's accidental + means the workload inherits " +
		"the node's broader image-pull permissions. Audit-verify per " +
		"workload whether the implicit-credential fallback is intended.",
	Remediation: "Define a Secret of type `kubernetes.io/dockerconfigjson` " +
		"+ reference it via `spec.imagePullSecrets`. For ECR / GCR / " +
		"ACR, prefer the cloud-provider native auth (IRSA on EKS, " +
		"Workload Identity on GKE).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.5.15", "A.8.32"},
		"cis-v8":   {"6.7", "16.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "registry", "manual-verify"},
	Scanner: "supplychain.ImagePullSecret",
}

func ImagePullSecretPresent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		f := core.Finding{
			CheckID: CheckImagePullSecretPresent.ID, Severity: CheckImagePullSecretPresent.Severity,
			Resource: p.Ref(), Tags: CheckImagePullSecretPresent.Tags,
			Status:  core.StatusError,
			Message: fmt.Sprintf("pod %q: audit imagePullSecrets vs implicit node-level credentials (`kubectl get pod -n <ns> %s -o jsonpath='{.spec.imagePullSecrets}'`)", podDesc(p), p.Name),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 7. image pull policy = Always for mutable, Pinned for digest

var CheckImagePullPolicyConsistent = core.Check{
	ID:           "k8s-pod-image-pull-policy-consistent",
	Title:        "imagePullPolicy must be consistent with the tag pinning level",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "imagePullPolicy: IfNotPresent + a mutable tag = pod " +
		"on the same node can pull stale content if the tag has been " +
		"rewritten upstream. imagePullPolicy: Always + a sha256 digest " +
		"= every restart pulls + verifies the digest (waste, since the " +
		"digest is immutable). The right pairing:\n  - Digest-pinned " +
		"image    → IfNotPresent (verify is implicit in digest match).\n  " +
		"- Mutable-tagged image → Always (force re-pull).",
	Remediation: "Pair tag-pinning + pull-policy:\n  - sha256 digest: " +
		"imagePullPolicy: IfNotPresent\n  - mutable tag:   imagePullPolicy: " +
		"Always",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "image"},
	Scanner: "supplychain.ImagePullPolicyConsistent",
}

func ImagePullPolicyConsistent(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(k8scol.PodType) {
		bad := violatingContainers(p, func(c map[string]any) bool {
			pinned, _ := c["image_digest_pinned"].(bool)
			policy, _ := c["image_pull_policy"].(string)
			tag, _ := c["image_tag"].(string)
			tagLower := strings.ToLower(strings.TrimSpace(tag))
			mutable := tag == "" || mutableTagNames[tagLower]
			switch {
			case mutable && policy != "Always":
				return true
			case pinned && policy == "Always":
				return true
			default:
				return false
			}
		})
		findings = append(findings, podFinding(CheckImagePullPolicyConsistent, p, bad,
			"image pull policy inconsistent with tag-pinning level: %s",
			"image pull policy consistent with tag-pinning"))
	}
	return findings, nil
}

// ----- 8. image base-OS EOL (manual-verify) -----------------------

var CheckImageBaseEOL = core.Check{
	ID:           "k8s-pod-image-base-os-not-eol",
	Title:        "Container images should not be built on EOL base OS",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Base images on EOL distributions (debian:9, ubuntu:18.04, " +
		"alpine:3.10, centos:7) no longer receive security updates. " +
		"Manual-verify since determining the base requires registry " +
		"introspection (`crane manifest` + label parsing) or a vuln " +
		"scanner (Trivy, Grype) — both better fed via the v0.14 ingest " +
		"path than re-implemented in compliancekit.",
	Remediation: "Rebase onto a supported distribution. Use endoflife.date " +
		"as the canonical reference for support windows. Wire Trivy / " +
		"Grype output into compliancekit via `--ingest <scanner-output>` " +
		"for automated EOL detection.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.1", "7.3"},
	},
	Tags:    []string{"k8s", "supply-chain", "base-os", "manual-verify"},
	Scanner: "supplychain.ImageBaseEOL",
}

func ImageBaseEOL(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckImageBaseEOL,
		"audit base-OS support windows: `crane manifest <image> | jq '.config.Labels'` + cross-reference https://endoflife.date — or wire Trivy via compliancekit ingest")
}

// ----- 9. image registry reachable via TLS only (cluster-level) ---

var CheckRegistryTLSOnly = core.Check{
	ID:           "k8s-cluster-registry-tls-only",
	Title:        "All image registries used by the cluster should require TLS",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.ClusterType,
	Description: "An insecure-registry (HTTP, or HTTPS with a self-signed " +
		"cert the kubelet was configured to trust) breaks the supply-chain " +
		"signature/digest chain. Most managed K8s services reject " +
		"insecure registries by default; self-managed clusters can set " +
		"insecure-registries via /etc/containerd/config.toml — audit " +
		"required.",
	Remediation: "On self-managed kubelets: remove insecure_registries " +
		"entries from /etc/containerd/config.toml + restart containerd. " +
		"On EKS/GKE/DOKS: default posture is TLS-only; this check passes.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.5.14", "A.8.24"},
		"cis-v8":   {"3.10", "4.6"},
	},
	Tags:    []string{"k8s", "supply-chain", "registry", "manual-verify"},
	Scanner: "supplychain.RegistryTLSOnly",
}

func RegistryTLSOnly(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckRegistryTLSOnly,
		"on self-managed nodes: `ssh <node> 'grep -A 5 insecure_registries /etc/containerd/config.toml'` should return nothing")
}

// ----- 10. CIS image scan freshness (manual-verify) ---------------

var CheckImageScanFresh = core.Check{
	ID:           "k8s-pod-image-vuln-scan-fresh",
	Title:        "Images should have a Trivy / Grype scan within the last 7 days",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "supply-chain",
	ResourceType: k8scol.PodType,
	Description: "Image vulnerability scanning is point-in-time; CVEs are " +
		"disclosed continuously. A scan older than 7 days is at risk of " +
		"missing fresh CVEs in dependencies. Best practice: re-scan + " +
		"alert on new high/critical findings at least daily, or on every " +
		"new image push. Manual-verify since scan metadata lives in the " +
		"scanner's own database (ingest via v0.14 vulnerabilities.csv " +
		"closes this loop).",
	Remediation: "Schedule daily Trivy / Grype scans (`trivy image " +
		"--security-checks vuln <image>`) + ingest the results into " +
		"compliancekit via `--ingest trivy-json:<path>`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.1", "7.3", "7.4"},
	},
	Tags:    []string{"k8s", "supply-chain", "vuln-scan", "manual-verify"},
	Scanner: "supplychain.ImageScanFresh",
}

func ImageScanFresh(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return clusterManualVerify(g, CheckImageScanFresh,
		"audit per-image scan freshness — wire Trivy or Grype via compliancekit ingest for automated coverage")
}

// ---------- shared helpers --------------------------------------

// clusterManualVerify emits one StatusError finding per cluster
// context resource — the canonical manual-verify shape from v0.20
// adapted for k8s where the "per-host" unit is the cluster context.
func clusterManualVerify(g *core.ResourceGraph, check core.Check, hint string) ([]core.Finding, error) {
	findings := []core.Finding{}
	ctxs := g.ByType(k8scol.ClusterType)
	if len(ctxs) == 0 {
		return findings, nil
	}
	for _, c := range ctxs {
		findings = append(findings, core.Finding{
			CheckID: check.ID, Severity: check.Severity,
			Resource: c.Ref(), Tags: check.Tags,
			Status:  core.StatusError,
			Message: fmt.Sprintf("cluster %q: %s", c.Name, hint),
		})
	}
	return findings, nil
}

// imageRegistries returns the deduped list of registry hostnames used
// by every container in the pod. "docker.io" is implied for refs
// without an explicit registry; "library/" path-prefix for unqualified
// repos is normalized away.
func imageRegistries(p core.Resource) []string {
	seen := map[string]bool{}
	cs, _ := p.Attributes["containers"].([]any)
	for _, ci := range cs {
		c, ok := ci.(map[string]any)
		if !ok {
			continue
		}
		img, _ := c["image"].(string)
		reg := registryFromImage(img)
		if reg != "" {
			seen[reg] = true
		}
	}
	out := []string{}
	for r := range seen {
		out = append(out, r)
	}
	return out
}

// registryFromImage extracts the registry hostname from an image ref.
// Conventions:
//   - "nginx" / "library/nginx" → "docker.io"
//   - "ghcr.io/org/repo"        → "ghcr.io"
//   - "private:5000/img"        → "private:5000"
//
// Per the OCI distribution spec: split on the first '/' — if the head
// looks like a hostname (contains '.' or ':' or is literally
// "localhost") it IS the registry; otherwise the ref omits the
// registry and defaults to docker.io.
func registryFromImage(image string) string {
	image = strings.SplitN(image, "@", 2)[0] // strip digest first
	parts := strings.SplitN(image, "/", 2)
	if len(parts) < 2 {
		return "docker.io"
	}
	head := parts[0]
	if strings.ContainsAny(head, ".:") || head == "localhost" {
		return head
	}
	return "docker.io"
}

func init() {
	core.Register(CheckImageMutableTag, ImageMutableTag)
	core.Register(CheckImageEmptyTag, ImageEmptyTag)
	core.Register(CheckImageTrustedRegistry, ImageTrustedRegistry)
	core.Register(CheckImageCosignSignature, ImageCosignSignature)
	core.Register(CheckImageAttestation, ImageAttestation)
	core.Register(CheckImagePullSecretPresent, ImagePullSecretPresent)
	core.Register(CheckImagePullPolicyConsistent, ImagePullPolicyConsistent)
	core.Register(CheckImageBaseEOL, ImageBaseEOL)
	core.Register(CheckRegistryTLSOnly, RegistryTLSOnly)
	core.Register(CheckImageScanFresh, ImageScanFresh)
}
