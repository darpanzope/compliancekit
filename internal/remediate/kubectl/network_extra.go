package kubectl

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 4 — kubectl strategies for the 10 network-depth checks.

var networkExtraEntries = map[string]psExtraEntry{
	"k8s-ingress-no-configuration-snippet": {
		patch:    `kubectl annotate ingress <NAME> -n <NS> nginx.ingress.kubernetes.io/configuration-snippet-`,
		manifest: "# Remove from manifest:\nmetadata:\n  annotations:\n    # nginx.ingress.kubernetes.io/configuration-snippet: |     # DELETE\n    #   <raw nginx config>",
		risk:     remediate.RiskReview,
		notes:    "Removing the annotation may break custom routing — verify the same intent can be expressed via supported fields (rewrite-target, ssl-redirect, server-alias) before applying.",
	},
	"k8s-ingress-no-server-snippet": {
		patch:    `kubectl annotate ingress <NAME> -n <NS> nginx.ingress.kubernetes.io/server-snippet-`,
		manifest: "# Remove from manifest:\nmetadata:\n  annotations:\n    # nginx.ingress.kubernetes.io/server-snippet: |     # DELETE",
		risk:     remediate.RiskReview,
	},
	"k8s-ingress-no-auth-snippet": {
		patch:    `kubectl annotate ingress <NAME> -n <NS> nginx.ingress.kubernetes.io/auth-snippet-`,
		manifest: "# Remove from manifest + move auth to a side-car:\nmetadata:\n  annotations:\n    # nginx.ingress.kubernetes.io/auth-snippet: |     # DELETE\n    nginx.ingress.kubernetes.io/auth-url: https://auth.svc.cluster.local/verify\n    nginx.ingress.kubernetes.io/auth-signin: https://auth.svc.cluster.local/login",
		risk:     remediate.RiskReview,
		notes:    "If you genuinely need request-time auth logic, deploy oauth2-proxy or authelia as a sidecar/service + use auth-url annotations to delegate to it.",
	},
	"k8s-service-no-zero-cidr-source-range": {
		patch:    `kubectl patch svc <NAME> -n <NS> --type=json -p='[{"op":"replace","path":"/spec/loadBalancerSourceRanges","value":["203.0.113.0/24","198.51.100.0/24"]}]'`,
		manifest: "spec:\n  type: LoadBalancer\n  loadBalancerSourceRanges:\n    # Replace with actual ingress CIDRs:\n    - 203.0.113.0/24    # office VPN\n    - 198.51.100.0/24   # CI runners\n    # NEVER:\n    # - 0.0.0.0/0",
		risk:     remediate.RiskReview,
		notes:    "Replace 0.0.0.0/0 with actual ingress CIDRs. If you genuinely need internet-wide access, remove the field entirely so the manifest is honest.",
	},
	"k8s-networkpolicy-cloud-metadata-egress-blocked": {
		patch:    "# Apply the metadata-deny NetworkPolicy across every workload namespace:\nkubectl apply -f https://raw.githubusercontent.com/ahmetb/kubernetes-network-policy-recipes/master/14-deny-external-egress.yaml -n <NS>",
		manifest: "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny-cloud-metadata\n  namespace: <NS>\nspec:\n  podSelector: {}            # apply to every pod in the namespace\n  policyTypes: [Egress]\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n            except:\n              - 169.254.169.254/32     # AWS / GCP / Azure IMDS\n              - 169.254.170.2/32       # ECS task metadata\n              - fd00:ec2::254/128      # IMDSv6 (if dual-stack)\n    - to:\n        - namespaceSelector:           # allow intra-cluster\n            matchLabels:\n              kubernetes.io/metadata.name: <NS>",
		risk:     remediate.RiskReview,
		notes:    "Pair with IMDSv2-only enforcement on the node group launch template (EKS: HttpTokens: required, HttpPutResponseHopLimit: 1). On GKE / AKS no equivalent IMDSv2 — NetworkPolicy is the only mitigation.",
	},
	"k8s-ingress-no-lua-plugins": {
		patch:    `# Remove every lua-* + modsecurity-snippet annotation:\nkubectl annotate ingress <NAME> -n <NS> nginx.ingress.kubernetes.io/lua-resty-waf- nginx.ingress.kubernetes.io/modsecurity-snippet-`,
		manifest: "metadata:\n  annotations:\n    # Delete every lua-* + modsecurity-snippet annotation.\n    # Migrate Lua middleware to a sidecar nginx with curated bundles.",
		risk:     remediate.RiskReview,
	},
	"k8s-service-no-publish-not-ready-addresses": {
		patch:    `kubectl patch svc <NAME> -n <NS> --type=json -p='[{"op":"remove","path":"/spec/publishNotReadyAddresses"}]'`,
		manifest: "spec:\n  # publishNotReadyAddresses: true   # REMOVE — only safe on headless\n                                     # discovery services consumed by\n                                     # StatefulSet bootstrap",
		risk:     remediate.RiskReview,
		notes:    "Keep publishNotReadyAddresses=true ONLY for headless Services consumed by a single StatefulSet's bootstrap. Anywhere else, removing it stops routing traffic to pods failing readiness.",
	},
	"k8s-service-selector-too-broad": {
		patch:    `kubectl label deployment <NAME> -n <NS> app.kubernetes.io/instance=<unique-id> && kubectl patch svc <SVC> -n <NS> --type=json -p='[{"op":"add","path":"/spec/selector/app.kubernetes.io~1instance","value":"<unique-id>"}]'`,
		manifest: "# Add a discriminating label to BOTH pods + selector:\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: <name>\nspec:\n  template:\n    metadata:\n      labels:\n        app: <name>\n        app.kubernetes.io/instance: <unique-id>   # discriminator\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: <name>\nspec:\n  selector:\n    app: <name>\n    app.kubernetes.io/instance: <unique-id>     # matches",
		risk:     remediate.RiskReview,
		notes:    "Selectors are immutable on a Service — to change, delete + recreate the Service (causes brief connection loss to existing clients).",
	},
	"k8s-ingress-no-rules-defined": {
		patch:    `# Edit the Ingress to add explicit rules:\nkubectl edit ingress <NAME> -n <NS>`,
		manifest: "spec:\n  rules:\n    - host: app.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: app-svc\n                port:\n                  number: 80",
		risk:     remediate.RiskReview,
	},
	"k8s-service-mixed-tls-plaintext-ports": {
		patch:    `kubectl patch svc <NAME> -n <NS> --type=json -p='[{"op":"remove","path":"/spec/ports/0"}]'   # remove the port:80 entry — adjust index per actual position`,
		manifest: "spec:\n  ports:\n    # remove the port: 80 entry; terminate TLS at the Ingress instead:\n    - port: 443\n      targetPort: 8443\n      protocol: TCP\n---\n# Ingress handles the HTTP → HTTPS redirect:\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  annotations:\n    nginx.ingress.kubernetes.io/ssl-redirect: \"true\"\n    nginx.ingress.kubernetes.io/force-ssl-redirect: \"true\"",
		risk:     remediate.RiskReview,
	},
}

func init() {
	for id, e := range networkExtraEntries {
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

// v0.21 phase 10 — kubectl backfill for the 9 legacy network-tier
// check IDs that network.go (the v0.11 base) didn't carry kubectl
// strategies for. Covers NetworkPolicy depth + Ingress + Service.
// See backfill_helper.go for the renderer.
func init() {
	registerBackfillIDs(
		"k8s-ingress-dangerous-annotations",
		"k8s-ingress-default-backend",
		"k8s-networkpolicy-allow-all-egress",
		"k8s-networkpolicy-allow-all-ingress",
		"k8s-networkpolicy-empty-selector",
		"k8s-networkpolicy-from-all-namespaces",
		"k8s-networkpolicy-namespace-coverage",
		"k8s-service-loadbalancer-no-tls",
		"k8s-service-nodeport",
	)
}
