package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 4 — Terraform strategies for the 10 DOKS-depth checks
// (provider="kubernetes", service="doks"). DOKS clusters live as
// `digitalocean_kubernetes_cluster`; node pools as
// `digitalocean_kubernetes_node_pool`. Add-on installs (cert-manager,
// metrics-server, autoscaler) typically go through `helm_release` from
// the kubernetes/helm provider — those strategies render a documented
// example with the right release name + namespace.

func init() {
	register("tf-doks-version-supported",
		[]string{"k8s-doks-version-deprecated"}, renderTFDOKSVersion)
	register("tf-doks-nodepool-taints",
		[]string{"k8s-doks-nodepool-no-taints"}, renderTFDOKSTaints)
	register("tf-doks-nodepool-environment-tag",
		[]string{"k8s-doks-nodepool-no-environment-tag"}, renderTFDOKSEnvTag)
	register("tf-doks-nodepool-size-supported",
		[]string{"k8s-doks-nodepool-size-retired"}, renderTFDOKSSize)
	register("tf-doks-maintenance-quiet-hours",
		[]string{"k8s-doks-maintenance-window-loud-hours"}, renderTFDOKSMaintenance)
	register("tf-doks-control-plane-logging",
		[]string{"k8s-doks-control-plane-logging-exported"}, renderTFDOKSLogging)
	register("tf-doks-metrics-server",
		[]string{"k8s-doks-metrics-server-installed"}, renderTFDOKSMetricsServer)
	register("tf-doks-cert-manager",
		[]string{"k8s-doks-cert-manager-installed"}, renderTFDOKSCertManager)
	register("tf-doks-cluster-autoscaler",
		[]string{"k8s-doks-cluster-autoscaler-eligible"}, renderTFDOKSAutoscaler)
	register("tf-doks-pod-security-standards",
		[]string{"k8s-doks-pod-security-standards-baseline"}, renderTFDOKSPSA)
}

func renderTFDOKSVersion(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "CLUSTER")
	body := fmt.Sprintf(`resource "digitalocean_kubernetes_cluster" %q {
  name    = %q
  region  = "nyc3"
  version = "1.30.5-do.0"   # bump to current supported minor; check doctl k8s options versions list
  auto_upgrade  = true
  surge_upgrade = true
  ha            = true
  # ... node_pool block ...
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "doctl kubernetes options versions list",
		Notes:     "Stage in non-prod first. Auto-upgrade + maintenance window will keep the cluster on supported minors going forward.",
		Refs:      []string{"https://docs.digitalocean.com/products/kubernetes/details/supported-releases/"},
	}, nil
}

func renderTFDOKSTaints(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "POOL")
	body := fmt.Sprintf(`resource "digitalocean_kubernetes_node_pool" %q {
  cluster_id = digitalocean_kubernetes_cluster.main.id
  name       = %q
  size       = "s-4vcpu-8gb"
  min_nodes  = 2
  max_nodes  = 6
  auto_scale = true

  taint {
    key    = "dedicated"
    value  = "%s"
    effect = "NoSchedule"
  }

  tags = ["env:production", "pool:%s"]
}
`, tfIdent(name), name, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Add a matching toleration on the workloads that should land on this pool.",
		Refs:  []string{"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_node_pool"},
	}, nil
}

func renderTFDOKSEnvTag(f core.Finding) (remediate.Snippet, error) { return renderTFDOKSTaints(f) }

func renderTFDOKSSize(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "POOL")
	body := fmt.Sprintf(`resource "digitalocean_kubernetes_node_pool" %q {
  cluster_id = digitalocean_kubernetes_cluster.main.id
  name       = %q
  size       = "s-2vcpu-4gb"   # replace retired size
  min_nodes  = 2
  max_nodes  = 6
  auto_scale = true
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Recreate the pool on a supported size; drain workloads first if migrating.",
		Refs:  []string{"https://slugs.do-api.dev/"},
	}, nil
}

func renderTFDOKSMaintenance(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "CLUSTER")
	body := fmt.Sprintf(`resource "digitalocean_kubernetes_cluster" %q {
  name   = %q
  region = "nyc3"
  maintenance_policy {
    day        = "sunday"
    start_time = "04:00"   # UTC; pick a low-traffic hour
  }
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		Notes: "Window only matters when auto_upgrade=true OR DO triggers a security patch. Aim for off-peak in your primary customer timezone.",
	}, nil
}

func renderTFDOKSLogging(_ core.Finding) (remediate.Snippet, error) {
	body := `# Deploy a fluent-bit DaemonSet to forward control-plane + node logs.
# Helm release shape (requires kubernetes/helm providers configured to
# point at the DOKS cluster).

resource "helm_release" "fluent_bit" {
  name             = "fluent-bit"
  repository       = "https://fluent.github.io/helm-charts"
  chart            = "fluent-bit"
  namespace        = "logging"
  create_namespace = true

  values = [<<-EOT
    config:
      outputs: |
        [OUTPUT]
            Name  loki
            Match *
            host  loki.observability.svc
            port  3100
  EOT
  ]
}
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Swap Loki for Datadog / Splunk / Elastic per your platform. Aim for ≥90d retention to satisfy SOC2 CC7.2.",
		Refs:  []string{"https://docs.fluentbit.io/manual/installation/kubernetes"},
	}, nil
}

func renderTFDOKSMetricsServer(_ core.Finding) (remediate.Snippet, error) {
	body := `resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  namespace  = "kube-system"
  values = [<<-EOT
    args:
      - --kubelet-insecure-tls    # DOKS uses self-signed kubelet certs
      - --kubelet-preferred-address-types=InternalIP
  EOT
  ]
}
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n kube-system get deployment metrics-server",
		Notes:     "DOKS clusters created since 2023 ship metrics-server by default; this is for clusters that opted out.",
	}, nil
}

func renderTFDOKSCertManager(_ core.Finding) (remediate.Snippet, error) {
	body := `resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  namespace        = "cert-manager"
  create_namespace = true
  set {
    name  = "installCRDs"
    value = "true"
  }
}

# Then create a ClusterIssuer for Let's Encrypt + DNS01 via DO:
resource "kubernetes_manifest" "letsencrypt_issuer" {
  manifest = yamldecode(<<-YAML
    apiVersion: cert-manager.io/v1
    kind: ClusterIssuer
    metadata:
      name: letsencrypt-prod
    spec:
      acme:
        email: secops@example.com
        server: https://acme-v02.api.letsencrypt.org/directory
        privateKeySecretRef:
          name: letsencrypt-prod-key
        solvers:
          - dns01:
              webhook:
                groupName: acme.example.com
                solverName: digitalocean
  YAML
  )
}
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl -n cert-manager get pod -l app.kubernetes.io/instance=cert-manager",
		Notes:     "Requires cert-manager-webhook-digitalocean for DNS01 against DO. Pre-create the DO API token secret separately.",
		Refs:      []string{"https://cert-manager.io/docs/installation/helm/"},
	}, nil
}

func renderTFDOKSAutoscaler(f core.Finding) (remediate.Snippet, error) {
	// Native per-pool path is the simpler default. Render that.
	return renderTFDOKSTaints(f)
}

func renderTFDOKSPSA(_ core.Finding) (remediate.Snippet, error) {
	body := `# Label production namespaces with Pod Security Admission policy.
# kubernetes_labels works for in-place namespace patching.

resource "kubernetes_labels" "ns_production_psa" {
  api_version = "v1"
  kind        = "Namespace"
  metadata { name = "production" }
  labels = {
    "pod-security.kubernetes.io/enforce"         = "baseline"
    "pod-security.kubernetes.io/enforce-version" = "latest"
    "pod-security.kubernetes.io/warn"            = "restricted"
    "pod-security.kubernetes.io/audit"           = "restricted"
  }
}
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		VerifyCmd: "kubectl get ns production -o jsonpath='{.metadata.labels}'",
		Notes:     "Roll out warn= first to surface workloads that will fail enforce. Tighten enforce= over 2-week phases.",
		Refs:      []string{"https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
	}, nil
}
