package k8s

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 4 — DOKS add-on coverage + node-pool isolation +
// version hygiene + manual-verify on the dashboard-only / kubectl-
// only controls.
//
// REAL-DATA (5) read existing collector attrs (version, taints,
// tags, count). MANUAL-VERIFY (5) cover add-ons and cluster-internal
// configuration the DO API does not surface — the strategies render
// kubectl one-liners the operator runs against the cluster.
//
// All checks are under provider="kubernetes" service="doks" matching
// the existing pattern; this keeps them out of the DO parity ratchet
// (which only gates Provider == "digitalocean").

func newDOKSFinding(check compliancekit.Check, cluster compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: cluster.Ref(),
		Tags:     check.Tags,
	}
}

func doksManualVerify(check compliancekit.Check, cluster compliancekit.Resource, control, kubectlHint string) compliancekit.Finding {
	f := newDOKSFinding(check, cluster)
	f.Status = compliancekit.StatusError
	f.Message = fmt.Sprintf("doks cluster %q: %s — verify with %s (DO API does not surface this state)",
		cluster.Name, control, kubectlHint)
	return f
}

// ----- 1. version not deprecated ----------------------------------------

// doksDeprecatedMinors are minors DO has announced end-of-support for
// at the time the check shipped. Refreshed each release. Treat any
// match (prefix) on the cluster's version_slug as a fail.
var doksDeprecatedMinors = []string{"1.26.", "1.25.", "1.24.", "1.23.", "1.22."}

var CheckDOKSVersionSupported = compliancekit.Check{
	ID:           "k8s-doks-version-deprecated",
	Title:        "DOKS cluster version must not be on the DO deprecation list",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DigitalOcean unsupports DOKS minor versions roughly 14 " +
		"months after release. Once unsupported, the cluster stops " +
		"receiving control-plane patches and node-image refreshes — " +
		"CVE exposure climbs unbounded. Pin a supported minor; let " +
		"auto-upgrade keep it inside the supported window.",
	Remediation: "Upgrade in maintenance window: `doctl kubernetes cluster " +
		"upgrade <cluster-id> --version=1.30.x-do.x`. Stage in non-prod " +
		"first; verify no PSA / admission-webhook breakage.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.3", "7.4"},
	},
	Tags:    []string{"k8s", "doks", "version", "patching"},
	Scanner: "doks.VersionSupported",
}

func DOKSVersionSupported(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		ver, _ := c.Attributes["version"].(string)
		f := newDOKSFinding(CheckDOKSVersionSupported, c)
		deprecated := false
		for _, prefix := range doksDeprecatedMinors {
			if strings.HasPrefix(ver, prefix) {
				deprecated = true
				break
			}
		}
		if deprecated {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: version %q is in the deprecated list", c.Name, ver)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: version %q is supported", c.Name, ver)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. nodepool taints isolation -----------------------------------

var CheckDOKSNodepoolTaints = compliancekit.Check{
	ID:           "k8s-doks-nodepool-no-taints",
	Title:        "Non-default node pools should declare workload-isolation taints",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSNodePoolType,
	Description: "Multi-tenant DOKS clusters typically segregate workloads " +
		"by node pool (e.g. 'gpu', 'memory-optimised', 'ingress'). " +
		"Without taints, the scheduler treats every pool as fair game " +
		"and security-relevant isolation (egress proxies, secrets " +
		"vaults) shares hosts with general workloads. Default pools " +
		"can stay untainted; named pools should declare at least one.",
	Remediation: "`doctl kubernetes cluster node-pool update <c> <np> " +
		"--taint dedicated=gpu:NoSchedule`. Then set tolerations on " +
		"the workloads that should target the pool.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.18"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"k8s", "doks", "nodepool", "isolation"},
	Scanner: "doks.NodepoolTaints",
}

func DOKSNodepoolTaints(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, np := range g.ByType(docol.DOKSNodePoolType) {
		name := np.Name
		// Skip the implicit default-pool naming convention; only flag
		// explicitly-named pools.
		if name == "" || strings.HasPrefix(name, "default") || name == "pool-1" {
			continue
		}
		taints, _ := np.Attributes["taints"].([]map[string]string)
		f := newDOKSFinding(CheckDOKSNodepoolTaints, np)
		if len(taints) > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: %d taint(s) declared", name, len(taints))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: no taints declared (no workload-isolation pressure)", name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. nodepool environment tag --------------------------------------

var CheckDOKSNodepoolEnvironmentTag = compliancekit.Check{
	ID:           "k8s-doks-nodepool-no-environment-tag",
	Title:        "DOKS node pools should declare an environment tag",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSNodePoolType,
	Description: "Tagging a node pool with the environment (prod / " +
		"staging / dev) lets billing reports + monitoring alerts route " +
		"on tag without re-deriving from the cluster name. CIS Controls " +
		"v8 1.1 expects inventory classification at the asset level.",
	Remediation: "Add a tag at create: `doctl kubernetes cluster node-pool " +
		"create <c> --tag=env:production`. Existing pools cannot be " +
		"retagged via doctl; recreate or use the TF resource.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"k8s", "doks", "nodepool", "tagging"},
	Scanner: "doks.NodepoolEnvironmentTag",
}

func DOKSNodepoolEnvironmentTag(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, np := range g.ByType(docol.DOKSNodePoolType) {
		tags, _ := np.Attributes["tags"].([]string)
		f := newDOKSFinding(CheckDOKSNodepoolEnvironmentTag, np)
		hasEnv := false
		for _, t := range tags {
			if strings.HasPrefix(strings.ToLower(t), "env:") || strings.HasPrefix(strings.ToLower(t), "environment:") {
				hasEnv = true
				break
			}
		}
		if hasEnv {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: environment tag present", np.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: no environment tag", np.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. nodepool size class within supported list ------------------

// doksRetiredSizes are slug prefixes DO has retired from the DOKS
// catalog. A cluster running on a retired size cannot scale up
// further — new node creation fails.
var doksRetiredSizes = []string{"s-1vcpu-1gb", "s-1vcpu-2gb"}

var CheckDOKSNodepoolSizeSupported = compliancekit.Check{
	ID:           "k8s-doks-nodepool-size-retired",
	Title:        "DOKS node pools must not use retired droplet sizes",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSNodePoolType,
	Description: "DO periodically retires droplet sizes from the DOKS " +
		"catalog. Pools on retired sizes cannot accept new nodes " +
		"(autoscaling and replacement on failure both fail), and any " +
		"pool with autoscaling = on + a retired size is one bad reboot " +
		"away from being undersized.",
	Remediation: "Recreate the pool on a supported size: `doctl kubernetes " +
		"cluster node-pool create <c> --name <new> --size s-2vcpu-4gb` " +
		"then `delete` the old pool. Drain workloads first.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"k8s", "doks", "nodepool", "sizing"},
	Scanner: "doks.NodepoolSizeSupported",
}

func DOKSNodepoolSizeSupported(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, np := range g.ByType(docol.DOKSNodePoolType) {
		size, _ := np.Attributes["size"].(string)
		f := newDOKSFinding(CheckDOKSNodepoolSizeSupported, np)
		retired := false
		for _, r := range doksRetiredSizes {
			if size == r {
				retired = true
				break
			}
		}
		if retired {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: size %q is retired from the DOKS catalog", np.Name, size)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: size %q is supported", np.Name, size)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. cluster maintenance window covers production-quiet hours ----

var CheckDOKSMaintenanceQuietHours = compliancekit.Check{
	ID:           "k8s-doks-maintenance-window-loud-hours",
	Title:        "Maintenance window should fall outside business hours",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS auto-upgrades + node-image refreshes run in the " +
		"maintenance window. A window between 09:00-17:00 UTC catches " +
		"most western business hours; production clusters should pick " +
		"a quieter zone (typically 03:00-05:00 in the cluster's primary " +
		"customer timezone). This is a hygiene check, not a hard fail.",
	Remediation: "`doctl kubernetes cluster update <c> --maintenance-window=" +
		"sunday=04:00`. Pick a day + hour that matches your traffic " +
		"low. Pair with `do-account-monitoring-alert-coverage` so a " +
		"maintenance-induced regression pages someone.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.4"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "doks", "maintenance", "ops-hygiene"},
	Scanner: "doks.MaintenanceQuietHours",
}

func DOKSMaintenanceQuietHours(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		mw, _ := c.Attributes["maintenance_window"].(string)
		f := newDOKSFinding(CheckDOKSMaintenanceQuietHours, c)
		switch {
		case mw == "":
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: no maintenance window pinned", c.Name)
		case looksLikeBusinessHour(mw):
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: maintenance window %q overlaps business hours", c.Name, mw)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: maintenance window %q is outside business hours", c.Name, mw)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// looksLikeBusinessHour returns true if the maintenance window's hour
// component falls between 09 and 17 (UTC). Conservative approximation;
// operators flag false positives via waivers.yaml.
func looksLikeBusinessHour(mw string) bool {
	// mw shape from collector: "<day> <HH:MM>".
	parts := strings.Fields(mw)
	if len(parts) != 2 {
		return false
	}
	hh := parts[1]
	if len(hh) < 2 {
		return false
	}
	switch hh[:2] {
	case "09", "10", "11", "12", "13", "14", "15", "16", "17":
		return true
	}
	return false
}

// ----- 6. manual: control-plane logging exported ----------------------

var CheckDOKSControlPlaneLogging = compliancekit.Check{
	ID:           "k8s-doks-control-plane-logging-exported",
	Title:        "DOKS control-plane logs must be exported (API audit, scheduler, controller-manager)",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DigitalOcean exposes control-plane logs only via the " +
		"`doctl kubernetes cluster logs` follow command; there is no " +
		"native log-export configuration in the DO API. Production " +
		"clusters must forward those logs to a long-retention sink " +
		"(Datadog, Loki, ELK) — SOC2 CC7.2 + ISO A.8.15 + CIS 8.5 all " +
		"require ≥90 day audit-log retention with tamper-evident " +
		"storage.",
	Remediation: "Two paths: (1) deploy a vector / fluent-bit DaemonSet " +
		"to forward node logs + scrape /var/log/kube-apiserver-audit; " +
		"(2) install the DO Datadog add-on if you're already a Datadog " +
		"customer (covers control-plane + workload logs in one). " +
		"Document the sink + retention SLA in the runbook.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.1", "8.5"},
	},
	Tags:    []string{"k8s", "doks", "audit-trail", "manual-verify"},
	Scanner: "doks.ControlPlaneLogging",
}

func DOKSControlPlaneLogging(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		findings = append(findings,
			doksManualVerify(CheckDOKSControlPlaneLogging, c,
				"control-plane log export sink",
				"`kubectl -n kube-system get daemonset | grep -E 'vector|fluent|datadog'`"))
	}
	return findings, nil
}

// ----- 7. manual: metrics-server installed ----------------------------

var CheckDOKSMetricsServer = compliancekit.Check{
	ID:           "k8s-doks-metrics-server-installed",
	Title:        "metrics-server must be installed (HPA + kubectl top dependency)",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS ships metrics-server in the default add-on set " +
		"but operators can opt out, and clusters older than 2023 may " +
		"have been provisioned without it. Without metrics-server, " +
		"HorizontalPodAutoscaler and `kubectl top` both fail silently. " +
		"This check is manual-verify because there's no DO API for " +
		"add-on state — operators run kubectl against the cluster.",
	Remediation: "Confirm: `kubectl -n kube-system get deployment " +
		"metrics-server`. Install if missing: " +
		"`kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "doks", "addon", "manual-verify"},
	Scanner: "doks.MetricsServer",
}

func DOKSMetricsServer(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		findings = append(findings,
			doksManualVerify(CheckDOKSMetricsServer, c,
				"metrics-server deployment",
				"`kubectl -n kube-system get deployment metrics-server`"))
	}
	return findings, nil
}

// ----- 8. manual: cert-manager installed ------------------------------

var CheckDOKSCertManager = compliancekit.Check{
	ID:           "k8s-doks-cert-manager-installed",
	Title:        "cert-manager (or equivalent) must manage workload TLS certificates",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS does not bundle cert-manager. Without it (or an " +
		"equivalent like external-dns-issued certs or a service mesh's " +
		"mTLS plane), workload TLS is operator-driven — manual rotation, " +
		"manual issuance, easy to miss. SOC2 CC6.7 + ISO A.8.24 expect " +
		"automated certificate lifecycle.",
	Remediation: "Install cert-manager via Helm: " +
		"`helm repo add jetstack https://charts.jetstack.io && " +
		"helm install cert-manager jetstack/cert-manager -n cert-manager " +
		"--create-namespace --set installCRDs=true`. Then create a " +
		"ClusterIssuer for Let's Encrypt + DNS01 backed by the DO " +
		"webhook (cert-manager-webhook-digitalocean).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"k8s", "doks", "addon", "tls", "manual-verify"},
	Scanner: "doks.CertManager",
}

func DOKSCertManager(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		findings = append(findings,
			doksManualVerify(CheckDOKSCertManager, c,
				"cert-manager (or equivalent) installation",
				"`kubectl -n cert-manager get deployment cert-manager` or `kubectl get crd | grep cert-manager.io`"))
	}
	return findings, nil
}

// ----- 9. manual: cluster autoscaler add-on ---------------------------

var CheckDOKSClusterAutoscaler = compliancekit.Check{
	ID:           "k8s-doks-cluster-autoscaler-eligible",
	Title:        "Production clusters should run cluster-autoscaler (or use DO's built-in)",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS provides per-node-pool autoscaling natively " +
		"(captured by k8s-doks-nodepool-no-autoscale). For clusters " +
		"with many node pools or cross-pool scaling needs, the " +
		"upstream cluster-autoscaler with the DO provider gives finer " +
		"control. Either is acceptable; what's NOT acceptable is " +
		"static node counts on a production cluster.",
	Remediation: "Default: enable per-pool autoscaling " +
		"(`doctl kubernetes cluster node-pool update <c> <np> " +
		"--auto-scale --min-nodes=2 --max-nodes=10`). Advanced: deploy " +
		"upstream cluster-autoscaler with `--cloud-provider=digitalocean`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.4"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "doks", "addon", "autoscaling", "manual-verify"},
	Scanner: "doks.ClusterAutoscaler",
}

func DOKSClusterAutoscaler(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		findings = append(findings,
			doksManualVerify(CheckDOKSClusterAutoscaler, c,
				"cluster autoscaling strategy",
				"`doctl kubernetes cluster node-pool list <cluster-id>` then verify auto-scale + min/max per pool"))
	}
	return findings, nil
}

// ----- 10. manual: Pod Security Standards baseline ---------------------

var CheckDOKSPodSecurityStandards = compliancekit.Check{
	ID:           "k8s-doks-pod-security-standards-baseline",
	Title:        "Pod Security Admission must enforce ≥ baseline on production namespaces",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "PodSecurityPolicy is removed; Pod Security Admission " +
		"(PSA) labels namespaces with enforce / audit / warn policies " +
		"at baseline or restricted level. DOKS clusters default PSA to " +
		"OFF in non-system namespaces. SOC2 CC6.6 + ISO A.8.18 + CIS " +
		"K8s 5.2 each require pod-level security defaults; this finding " +
		"flags the gap so the operator confirms enforcement is on.",
	Remediation: "Label production namespaces: " +
		"`kubectl label ns <ns> " +
		"pod-security.kubernetes.io/enforce=baseline " +
		"pod-security.kubernetes.io/warn=restricted " +
		"pod-security.kubernetes.io/audit=restricted`. Roll out " +
		"`warn=` first to find offending workloads, then flip enforce.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.18"},
		"cis-v8":   {"4.6"},
	},
	Tags:    []string{"k8s", "doks", "psa", "manual-verify"},
	Scanner: "doks.PodSecurityStandards",
}

func DOKSPodSecurityStandards(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		findings = append(findings,
			doksManualVerify(CheckDOKSPodSecurityStandards, c,
				"Pod Security Admission enforcement state",
				"`kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.metadata.labels.pod-security\\.kubernetes\\.io/enforce}{\"\\n\"}{end}'`"))
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckDOKSVersionSupported, DOKSVersionSupported)
	compliancekit.Register(CheckDOKSNodepoolTaints, DOKSNodepoolTaints)
	compliancekit.Register(CheckDOKSNodepoolEnvironmentTag, DOKSNodepoolEnvironmentTag)
	compliancekit.Register(CheckDOKSNodepoolSizeSupported, DOKSNodepoolSizeSupported)
	compliancekit.Register(CheckDOKSMaintenanceQuietHours, DOKSMaintenanceQuietHours)
	compliancekit.Register(CheckDOKSControlPlaneLogging, DOKSControlPlaneLogging)
	compliancekit.Register(CheckDOKSMetricsServer, DOKSMetricsServer)
	compliancekit.Register(CheckDOKSCertManager, DOKSCertManager)
	compliancekit.Register(CheckDOKSClusterAutoscaler, DOKSClusterAutoscaler)
	compliancekit.Register(CheckDOKSPodSecurityStandards, DOKSPodSecurityStandards)
}
