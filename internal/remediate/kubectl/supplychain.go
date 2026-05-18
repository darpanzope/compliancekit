package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 5 — kubectl strategies for the 10 supply-chain checks.

var supplychainEntries = map[string]psExtraEntry{
	"k8s-pod-image-tag-not-mutable": {
		patch:    `# Replace mutable tag with semver tag or digest:\nkubectl set image deployment/<NAME> <CONTAINER>=<IMG>:v1.2.3 -n <NS>\n# OR digest-pinned:\nkubectl set image deployment/<NAME> <CONTAINER>=<IMG>@sha256:abc... -n <NS>`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3            # semver tag\n          # or stronger:\n          # image: nginx@sha256:abc...   # digest-pinned",
		risk:     remediate.RiskReview,
		notes:    "Wire Renovate / dependabot to update the semver tag automatically — keeps the floor high without manual rewrites.",
	},
	"k8s-pod-image-tag-not-empty": {
		patch:    `kubectl set image deployment/<NAME> <CONTAINER>=<IMG>:<TAG> -n <NS>`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25.3   # explicit tag\n          # NOT: image: nginx",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-image-from-trusted-registry": {
		patch:    "# Mirror upstream into the org registry, then re-tag:\ncrane copy docker.io/nginx:1.25.3 myregistry.example.com/mirror/nginx:1.25.3\nkubectl set image deployment/<NAME> <CONTAINER>=myregistry.example.com/mirror/nginx:1.25.3 -n <NS>",
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          # Pull from org-controlled registry only:\n          image: myregistry.example.com/mirror/nginx:1.25.3\n---\n# Enforce at admission via Kyverno:\napiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: restrict-image-registries\nspec:\n  validationFailureAction: enforce\n  rules:\n    - name: registry-allowlist\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n      validate:\n        message: \"images may only be pulled from approved registries\"\n        pattern:\n          spec:\n            containers:\n              - image: \"myregistry.example.com/* | quay.io/sigstore/*\"",
		risk:     remediate.RiskReview,
		notes:    "Mirror upstream images via `crane copy` or a pull-through cache (Harbor, Sonatype Nexus) so the org controls the registry surface. Pair with a Kyverno or Gatekeeper allowlist policy at admission.",
	},
	"k8s-pod-image-cosign-signature-verified": {
		patch:    "# Install sigstore policy-controller (cosign-verifying admission):\nhelm install policy-controller sigstore/policy-controller -n cosign-system --create-namespace\n# Or Kyverno verify-images (no extra controller needed if Kyverno is already deployed):\nkubectl apply -f https://raw.githubusercontent.com/kyverno/policies/main/best-practices/verify_image/verify_image.yaml",
		manifest: "# Kyverno verify-images example:\napiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: verify-image-cosign\nspec:\n  validationFailureAction: enforce\n  background: false\n  rules:\n    - name: verify-signature\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n      verifyImages:\n        - imageReferences:\n            - \"ghcr.io/myorg/*\"\n          attestors:\n            - entries:\n                - keys:\n                    publicKeys: |-\n                      -----BEGIN PUBLIC KEY-----\n                      <cosign public key here>\n                      -----END PUBLIC KEY-----",
		risk:     remediate.RiskReview,
		notes:    "Use keyless verification (entries: - keyless: identity, issuer) for GitHub-Actions-built images so the trust roots in the OIDC chain, not in a long-lived key.",
	},
	"k8s-pod-image-attestation-required": {
		patch:    "# Generate SLSA provenance with cosign:\ncosign attest --predicate provenance.json --type slsaprovenance <IMAGE>\n# Verify at admission:\ncosign verify-attestation --type slsaprovenance --certificate-identity-regexp ... <IMAGE>",
		manifest: "# Kyverno verify-attestation policy:\napiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: verify-slsa-attestation\nspec:\n  validationFailureAction: enforce\n  rules:\n    - name: verify-build-provenance\n      match:\n        any:\n          - resources:\n              kinds: [Pod]\n      verifyImages:\n        - imageReferences:\n            - \"ghcr.io/myorg/*\"\n          attestations:\n            - predicateType: https://slsa.dev/provenance/v0.2\n              attestors:\n                - entries:\n                    - keyless:\n                        subject: \"https://github.com/myorg/repo/.github/workflows/release.yml@*\"\n                        issuer: \"https://token.actions.githubusercontent.com\"",
		risk:     remediate.RiskReview,
	},
	"k8s-pod-image-pull-secret-set": {
		patch:    `kubectl create secret docker-registry regcred -n <NS> --docker-server=<REG> --docker-username=<U> --docker-password=<P>\nkubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"add","path":"/spec/template/spec/imagePullSecrets","value":[{"name":"regcred"}]}]'`,
		manifest: "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: regcred\n  namespace: <ns>\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: <base64-encoded auth>\n---\nspec:\n  template:\n    spec:\n      imagePullSecrets:\n        - name: regcred\n      # Or use cloud-provider native auth:\n      # serviceAccountName: my-irsa-sa   # EKS IRSA\n      # serviceAccountName: my-wi-sa     # GKE Workload Identity",
		risk:     remediate.RiskReview,
		notes:    "Prefer cloud-provider native auth (IRSA on EKS, Workload Identity on GKE, Azure AD Workload Identity on AKS) over long-lived dockerconfigjson Secrets.",
	},
	"k8s-pod-image-pull-policy-consistent": {
		patch:    `kubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Always"}]'   # for mutable tags\n# OR\nkubectl patch deployment <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]'  # for digest-pinned`,
		manifest: "spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          # Mutable tag — force re-pull every restart:\n          image: nginx:latest\n          imagePullPolicy: Always\n        - name: app-pinned\n          # Digest-pinned — IfNotPresent is enough (digest verifies):\n          image: nginx@sha256:abc...\n          imagePullPolicy: IfNotPresent",
		risk:     remediate.RiskSafe,
	},
	"k8s-pod-image-base-os-not-eol": {
		patch:    "# Rebase the Dockerfile + rebuild:\n# sed -i 's|FROM debian:9|FROM debian:12|' Dockerfile\ndocker build -t myorg/app:v2 .\nkubectl set image deployment/<NAME> <CONTAINER>=myorg/app:v2 -n <NS>",
		manifest: "# Rebase to a supported distro in the Dockerfile:\nFROM debian:12-slim   # supported through Jun 2028\n# NOT: FROM debian:9 (EOL Jun 2022) or ubuntu:18.04 (EOL Apr 2023)\n# Reference: https://endoflife.date/",
		risk:     remediate.RiskReview,
		notes:    "Wire Trivy or Grype into compliancekit via `--ingest trivy-json:<path>` so EOL detection is automatic on every scan.",
	},
	"k8s-cluster-registry-tls-only": {
		patch:    "# On every self-managed node, edit /etc/containerd/config.toml + remove\n# any [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.<host>.tls]\n# insecure_skip_verify entries, then:\nsudo systemctl restart containerd",
		manifest: "# /etc/containerd/config.toml — remove any insecure_skip_verify lines:\n#\n# [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"insecure.registry:5000\".tls]\n#   insecure_skip_verify = true     # DELETE\n#\n# Also remove any http:// registries from your image manifests.",
		risk:     remediate.RiskManual,
		notes:    "On managed K8s (EKS, GKE, DOKS) this is enforced by the cloud provider — check passes by default. On self-managed kubeadm clusters this is the canonical insecure-registry escape.",
	},
	"k8s-pod-image-vuln-scan-fresh": {
		patch:    "# Re-scan + ingest into compliancekit:\ntrivy image --format json --output /tmp/trivy.json <IMAGE>\ncompliancekit scan --ingest trivy-json:/tmp/trivy.json ...",
		manifest: "# CI workflow (GitHub Actions example):\nname: nightly-image-scan\non:\n  schedule:\n    - cron: \"0 3 * * *\"\njobs:\n  scan:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: aquasecurity/trivy-action@master\n        with:\n          image-ref: ghcr.io/myorg/app:latest\n          format: json\n          output: trivy.json\n      - run: compliancekit scan --ingest trivy-json:trivy.json --output sarif",
		risk:     remediate.RiskSafe,
	},
}

func init() {
	for id, e := range supplychainEntries {
		id := id
		e := e
		register("kubectl-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := "# === kubectl patch ===\n" + e.patch + "\n\n# === Manifest (GitOps) ===\n" + e.manifest + "\n"
			return remediate.Snippet{
				Risk: e.risk, Idempotent: true, Content: body,
				Notes: e.notes,
			}, nil
		})
	}
}
