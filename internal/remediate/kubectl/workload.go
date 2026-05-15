package kubectl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

func init() {
	register("k8s-deployment-pdb-missing",
		[]string{"k8s-deployment-pdb-missing", "k8s-statefulset-pdb-missing"},
		renderPDBMissing)
	register("k8s-deployment-min-replicas",
		[]string{"k8s-deployment-min-replicas"},
		renderMinReplicas)
	register("k8s-deployment-anti-affinity",
		[]string{"k8s-deployment-anti-affinity"},
		renderAntiAffinity)
	register("k8s-deployment-rolling-update",
		[]string{"k8s-deployment-rolling-update"},
		renderRollingUpdate)
	register("k8s-pod-liveness-probe",
		[]string{"k8s-pod-liveness-probe"},
		renderLivenessProbe)
	register("k8s-pod-resource-limits",
		[]string{"k8s-pod-resource-limits"},
		renderResourceLimits)
	register("k8s-pod-resource-requests",
		[]string{"k8s-pod-resource-requests"},
		renderResourceRequests)
	register("k8s-ingress-tls-missing",
		[]string{"k8s-ingress-tls-missing"},
		renderIngressTLS)
	register("k8s-ingress-class-set",
		[]string{"k8s-ingress-class-set"},
		renderIngressClass)
	register("k8s-service-loadbalancer-source-ranges",
		[]string{"k8s-service-loadbalancer-source-ranges"},
		renderServiceSourceRanges)
	register("k8s-service-external-ips",
		[]string{"k8s-service-external-ips"},
		renderServiceExternalIPs)
	register("k8s-networkpolicy-default-deny",
		[]string{
			"k8s-networkpolicy-default-deny-ingress",
			"k8s-networkpolicy-default-deny-egress",
			"k8s-service-public-without-network-policy",
		},
		renderNetworkPolicyDefaultDeny)
}

func renderPDBMissing(f core.Finding) (remediate.Snippet, error) {
	_, ns, name := workloadFromResource(f)
	manifest := fmt.Sprintf(`apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: %s-pdb
  namespace: %s
spec:
  minAvailable: 1   # or use maxUnavailable: 1 for larger replica sets
  selector:
    matchLabels:
      app: %s        # MUST match the workload's pod template labels
`, name, ns, name)
	cmd := fmt.Sprintf("kubectl apply -n %s -f - <<'EOF'\n%sEOF", render.ShellQuote(ns), manifest)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl get pdb -n %s %s-pdb", render.ShellQuote(ns), render.ShellQuote(name)),
		Notes:      "Adjust the selector to match the workload's actual pod labels (the example assumes app=<name>). PDBs are evaluated by the eviction API (drain, autoscaler scale-down, node upgrades); without one a single eviction can take all replicas down.",
		Refs: []string{
			"https://kubernetes.io/docs/tasks/run-application/configure-pdb/",
		},
	}, nil
}

func renderMinReplicas(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  replicas: 3`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "3 replicas is the minimum for surviving a node failure with a PDB minAvailable=1. For latency-critical workloads scale higher; for batch / scheduled work the finding is a false positive and can be waived.",
	}, nil
}

func renderAntiAffinity(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := fmt.Sprintf(`spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: %s     # match this workload's pods
              topologyKey: kubernetes.io/hostname`, name)
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Preferred (not required) anti-affinity by node — the scheduler tries to spread pods across nodes but won't fail to schedule if it can't. For workloads that absolutely require multi-AZ replication, change preferredDuringScheduling… to requiredDuringScheduling… and use topology.kubernetes.io/zone.",
	}, nil
}

func renderRollingUpdate(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Default rolling update keeps 25% extra capacity available during deploys. For latency-sensitive workloads set maxUnavailable to 0; for batch workloads set both higher to deploy faster.",
	}, nil
}

func renderLivenessProbe(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        livenessProbe:
          httpGet:
            path: /healthz       # or /-/healthy, /actuator/health, etc.
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 20
          failureThreshold: 3`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Liveness probes restart hung containers; readiness probes (recommend adding both) gate traffic. Be careful with liveness — a probe that flaps under load amplifies the load. initialDelaySeconds should exceed your slowest startup case; use a startupProbe for apps with multi-minute warmup.",
	}, nil
}

func renderResourceLimits(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        resources:
          limits:
            cpu: 1
            memory: 1Gi`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Limits are upper bounds — exceeding memory triggers OOMKill; exceeding CPU triggers throttling. Right-size based on actual pod usage (kubectl top pod, Prometheus, Grafana). Setting limits == requests gives QoS Guaranteed (best for latency-critical workloads).",
	}, nil
}

func renderResourceRequests(f core.Finding) (remediate.Snippet, error) {
	kind, ns, name := workloadFromResource(f)
	patch := `spec:
  template:
    spec:
      containers:
      - name: REPLACE_WITH_CONTAINER_NAME
        resources:
          requests:
            cpu: 100m
            memory: 128Mi`
	cmd := kubectlPatch(kind, ns, name, patch)
	return remediate.Snippet{
		Risk:       remediate.RiskSafe,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Requests are the scheduler's input — without them, pods schedule on any node and contend with neighbors. 100m + 128Mi is a safe starting point for a small service; tune up based on observed usage.",
	}, nil
}

func renderIngressTLS(f core.Finding) (remediate.Snippet, error) {
	_, ns, name := workloadFromResource(f)
	manifest := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod   # if using cert-manager
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - REPLACE_WITH_YOUR_HOSTNAME
    secretName: %s-tls
  rules:
  - host: REPLACE_WITH_YOUR_HOSTNAME
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: REPLACE_WITH_SERVICE_NAME
            port:
              number: 80
`, name, ns, name)
	cmd := fmt.Sprintf("kubectl apply -n %s -f - <<'EOF'\n%sEOF", render.ShellQuote(ns), manifest)
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		Notes:      "Assumes cert-manager + letsencrypt-prod ClusterIssuer. If you manage certs manually, pre-create the secret %s-tls with tls.crt + tls.key and remove the cert-manager annotation.",
		Refs: []string{
			"https://cert-manager.io/docs/usage/ingress/",
		},
	}, nil
}

func renderIngressClass(f core.Finding) (remediate.Snippet, error) {
	_, ns, name := workloadFromResource(f)
	patch := `spec:
  ingressClassName: nginx     # or alb / traefik / your-ingress-class`
	cmd := fmt.Sprintf("kubectl patch ingress %s -n %s --type=strategic --patch %s",
		render.ShellQuote(name), render.ShellQuote(ns), render.ShellQuote(patch))
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Pin the ingress controller explicitly — relying on the default IngressClass breaks when a cluster admin changes which controller is default. Use `kubectl get ingressclass` to discover the canonical name in your cluster.",
	}, nil
}

func renderServiceSourceRanges(f core.Finding) (remediate.Snippet, error) {
	_, ns, name := workloadFromResource(f)
	patch := `spec:
  loadBalancerSourceRanges:
  - 10.0.0.0/8      # internal corp range
  # - 0.0.0.0/0     # use only if the service is truly public`
	cmd := fmt.Sprintf("kubectl patch service %s -n %s --type=strategic --patch %s",
		render.ShellQuote(name), render.ShellQuote(ns), render.ShellQuote(patch))
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, patch+"\n"),
		Notes:      "Restricts which source CIDRs the LoadBalancer accepts. Requires your CNI / cloud LB to honor loadBalancerSourceRanges (AWS NLB, GKE LB, DO LB do; some on-prem CNIs ignore it).",
	}, nil
}

func renderServiceExternalIPs(f core.Finding) (remediate.Snippet, error) {
	_, ns, name := workloadFromResource(f)
	// JSON Patch operation to remove the externalIPs field entirely.
	jsonPatch := `[{"op":"remove","path":"/spec/externalIPs"}]`
	cmd := fmt.Sprintf("kubectl patch service %s -n %s --type=json -p %s",
		render.ShellQuote(name), render.ShellQuote(ns), render.ShellQuote(jsonPatch))
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: false,
		Content:    cmd,
		Notes:      "spec.externalIPs is a CVE class on its own (CVE-2020-8554, MITM via service-claim) — only useful in bare-metal scenarios. Remove it and route ingress through a proper LoadBalancer / Ingress controller.",
		Refs: []string{
			"https://github.com/kubernetes/kubernetes/issues/97076",
		},
	}, nil
}

func renderNetworkPolicyDefaultDeny(f core.Finding) (remediate.Snippet, error) {
	_, ns, _ := workloadFromResource(f)
	manifest := fmt.Sprintf(`# Default-deny ingress and egress for namespace %q. Apply, then add
# allow-rules per workload as needed. CAUTION: applying this in a
# namespace without per-workload allows will black-hole every pod.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  # Allow DNS to kube-dns so pods can resolve cluster.local + external
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
`, ns, ns, ns)
	cmd := fmt.Sprintf("kubectl apply -f - <<'EOF'\n%sEOF", manifest)
	notes := "Default-deny is non-trivial — before applying, audit every workload in the namespace and add allow-rules for each (DB connections, S3 endpoints, service-mesh sidecars). Most clusters end up in 'allow all' indefinitely because the audit work was never scheduled; do this incrementally per workload."
	return remediate.Snippet{
		Risk:       remediate.RiskReview,
		Idempotent: true,
		Content:    patchAndManifest(cmd, manifest),
		VerifyCmd:  fmt.Sprintf("kubectl get networkpolicy -n %s", render.ShellQuote(ns)),
		Notes:      notes,
		Refs: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
		},
	}, nil
}
