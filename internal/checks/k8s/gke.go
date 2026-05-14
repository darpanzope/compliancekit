package k8s

import (
	"context"
	"fmt"
	"strings"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/internal/core"
)

// GKE enrichment checks. GKE resources come from the GCP collector
// (provider="gcp"); checks register under the kubernetes provider.

// ----- Private cluster ------------------------------------------

var CheckGKEPrivateCluster = core.Check{
	ID:           "k8s-gke-private-cluster",
	Title:        "GKE clusters should run with private nodes",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Without `privateClusterConfig.enablePrivateNodes`, " +
		"every node receives a public IP — a sprawling attack surface " +
		"plus accidental NAT-less egress. Private clusters keep node " +
		"IPs RFC1918 and route egress through Cloud NAT.",
	Remediation: "At cluster creation: `gcloud container clusters " +
		"create ... --enable-private-nodes`. Existing clusters need a " +
		"migration; the in-place toggle is limited.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5"},
	},
	Tags:    []string{"k8s", "gke", "private"},
	Scanner: "gke.PrivateCluster",
}

func GKEPrivateCluster(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeBoolCheck(g, CheckGKEPrivateCluster, "private_nodes",
		"private nodes enabled", "private nodes disabled (public node IPs)"), nil
}

// ----- Master authorized networks -------------------------------

var CheckGKEMasterAuthorized = core.Check{
	ID:           "k8s-gke-master-authorized-networks",
	Title:        "GKE clusters should restrict control-plane CIDR access",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Master Authorized Networks restricts which source " +
		"CIDRs can reach the GKE control plane. Without it (or with " +
		"0.0.0.0/0 in the list), kubectl from anywhere on the internet " +
		"can attempt to authenticate.",
	Remediation: "`gcloud container clusters update <c> " +
		"--enable-master-authorized-networks " +
		"--master-authorized-networks <cidr1>,<cidr2>`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5", "13.6"},
	},
	Tags:    []string{"k8s", "gke", "exposure"},
	Scanner: "gke.MasterAuthorized",
}

func GKEMasterAuthorized(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		cidrs, _ := c.Attributes["master_authorized_cidrs"].([]string)
		f := core.Finding{
			CheckID:  CheckGKEMasterAuthorized.ID,
			Severity: CheckGKEMasterAuthorized.Severity,
			Resource: c.Ref(),
			Tags:     CheckGKEMasterAuthorized.Tags,
		}
		switch {
		case len(cidrs) == 0:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: master authorized networks not configured", c.Name)
		case containsString(cidrs, "0.0.0.0/0"):
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: master authorized includes 0.0.0.0/0", c.Name)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: %d authorized CIDR(s)", c.Name, len(cidrs))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Workload Identity -----------------------------------------

var CheckGKEWorkloadIdentity = core.Check{
	ID:           "k8s-gke-workload-identity",
	Title:        "GKE clusters should enable Workload Identity",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Workload Identity is the GKE-native way to bind " +
		"Kubernetes ServiceAccounts to GCP IAM Service Accounts. " +
		"Without it, in-cluster workloads inherit the node's compute " +
		"engine SA — typically over-privileged and shared across every " +
		"workload on the node.",
	Remediation: "`gcloud container clusters update <c> " +
		"--workload-pool=<project>.svc.id.goog`. Annotate K8s SAs " +
		"with `iam.gke.io/gcp-service-account` to bind.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "gke", "iam"},
	Scanner: "gke.WorkloadIdentity",
}

func GKEWorkloadIdentity(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeBoolCheck(g, CheckGKEWorkloadIdentity, "workload_identity",
		"Workload Identity enabled", "Workload Identity disabled"), nil
}

// ----- Binary Authorization -------------------------------------

var CheckGKEBinaryAuth = core.Check{
	ID:           "k8s-gke-binary-authorization",
	Title:        "GKE clusters should enable Binary Authorization",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Binary Authorization enforces that container images " +
		"come from approved repositories and (optionally) carry " +
		"attestations from your CI pipeline. It is the GCP-native " +
		"supply-chain enforcement layer for K8s.",
	Remediation: "`gcloud container clusters update <c> " +
		"--binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE`. " +
		"Create attestation policies in Binary Authorization.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.8.30"},
		"cis-v8":   {"16.4", "16.6"},
	},
	Tags:    []string{"k8s", "gke", "supply-chain"},
	Scanner: "gke.BinaryAuth",
}

func GKEBinaryAuth(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		mode, _ := c.Attributes["binary_authorization"].(string)
		f := core.Finding{
			CheckID:  CheckGKEBinaryAuth.ID,
			Severity: CheckGKEBinaryAuth.Severity,
			Resource: c.Ref(),
			Tags:     CheckGKEBinaryAuth.Tags,
		}
		if mode == "PROJECT_SINGLETON_POLICY_ENFORCE" || mode == "POLICY_BINDINGS" || mode == "POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: binAuthz=%s", c.Name, mode)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: binAuthz=%s (not enforcing)", c.Name, mode)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Network policy -------------------------------------------

var CheckGKENetworkPolicy = core.Check{
	ID:           "k8s-gke-network-policy",
	Title:        "GKE clusters should enable network policy",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "GKE's network policy (Calico-based) is the enforcement " +
		"layer for NetworkPolicy resources. Without it, NetworkPolicy " +
		"objects exist but are no-ops — every workload can talk to " +
		"every other workload.",
	Remediation: "`gcloud container clusters update <c> " +
		"--enable-network-policy`. Existing clusters require a rolling " +
		"node-pool replacement; plan a maintenance window.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.1", "12.4"},
	},
	Tags:    []string{"k8s", "gke", "network-policy"},
	Scanner: "gke.NetworkPolicy",
}

func GKENetworkPolicy(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeBoolCheck(g, CheckGKENetworkPolicy, "network_policy",
		"network policy enabled", "network policy disabled (NetworkPolicy resources are no-ops)"), nil
}

// ----- Shielded nodes -------------------------------------------

var CheckGKEShieldedNodes = core.Check{
	ID:           "k8s-gke-shielded-nodes",
	Title:        "GKE clusters should enable Shielded Nodes",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Shielded Nodes turn on secure boot + integrity " +
		"monitoring on the underlying GCE instances. Without it, a " +
		"node-level bootkit / rootkit can persist across reboots and " +
		"silently exfiltrate kubelet credentials.",
	Remediation: "`gcloud container clusters update <c> " +
		"--enable-shielded-nodes`. Combine with shielded VM config " +
		"on each node pool.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.8"},
		"iso27001": {"A.8.2", "A.8.9"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "gke", "shielded"},
	Scanner: "gke.ShieldedNodes",
}

func GKEShieldedNodes(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeBoolCheck(g, CheckGKEShieldedNodes, "shielded_nodes",
		"shielded nodes enabled", "shielded nodes disabled"), nil
}

// ----- Release channel -------------------------------------------

var CheckGKEReleaseChannel = core.Check{
	ID:           "k8s-gke-release-channel",
	Title:        "GKE clusters should subscribe to a release channel",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Release channels (RAPID/REGULAR/STABLE) let Google " +
		"manage cluster upgrades on a predictable cadence. Without a " +
		"channel, the cluster sticks at its creation version forever " +
		"unless an operator manually triggers upgrades.",
	Remediation: "`gcloud container clusters update <c> " +
		"--release-channel=regular`. RAPID for dev, REGULAR for most, " +
		"STABLE for risk-averse production.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "gke", "upgrade"},
	Scanner: "gke.ReleaseChannel",
}

func GKEReleaseChannel(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		channel, _ := c.Attributes["release_channel"].(string)
		f := core.Finding{
			CheckID:  CheckGKEReleaseChannel.ID,
			Severity: CheckGKEReleaseChannel.Severity,
			Resource: c.Ref(),
			Tags:     CheckGKEReleaseChannel.Tags,
		}
		switch channel {
		case "RAPID", "REGULAR", "STABLE":
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: release channel=%s", c.Name, channel)
		default:
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: no release channel (channel=%s)", c.Name, channel)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Legacy ABAC -----------------------------------------------

var CheckGKELegacyABAC = core.Check{
	ID:           "k8s-gke-legacy-abac",
	Title:        "GKE clusters should not enable legacy ABAC",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Legacy ABAC predates RBAC; GKE leaves the flag exposed " +
		"for old clusters. With it on, every authenticated user has " +
		"broad permissions regardless of Role/ClusterRoleBinding.",
	Remediation: "`gcloud container clusters update <c> " +
		"--no-enable-legacy-authorization` (irreversible — verify RBAC " +
		"is correctly configured first).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"k8s", "gke", "rbac", "legacy"},
	Scanner: "gke.LegacyABAC",
}

func GKELegacyABAC(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		enabled, _ := c.Attributes["legacy_abac"].(bool)
		f := core.Finding{
			CheckID:  CheckGKELegacyABAC.ID,
			Severity: CheckGKELegacyABAC.Severity,
			Resource: c.Ref(),
			Tags:     CheckGKELegacyABAC.Tags,
		}
		if !enabled {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: legacy ABAC disabled", c.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: legacy ABAC enabled (bypasses RBAC)", c.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Cluster logging + monitoring -----------------------------

var CheckGKELoggingMonitoring = core.Check{
	ID:           "k8s-gke-logging-monitoring",
	Title:        "GKE clusters should enable logging and monitoring",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKEClusterType,
	Description: "Cloud Logging + Cloud Monitoring integration is the " +
		"GKE-native observability story. Without it, audit and " +
		"workload logs do not flow to Cloud Logging — degraded " +
		"incident response.",
	Remediation: "`gcloud container clusters update <c> " +
		"--logging=SYSTEM,WORKLOAD --monitoring=SYSTEM`. For " +
		"compliance-sensitive workloads also include `--logging=" +
		"...,APISERVER,AUDIT`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC4.1", "CC7.2"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"k8s", "gke", "logging"},
	Scanner: "gke.LoggingMonitoring",
}

func GKELoggingMonitoring(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		lg, _ := c.Attributes["logging_enabled"].(bool)
		mn, _ := c.Attributes["monitoring_enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckGKELoggingMonitoring.ID,
			Severity: CheckGKELoggingMonitoring.Severity,
			Resource: c.Ref(),
			Tags:     CheckGKELoggingMonitoring.Tags,
		}
		if lg && mn {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: logging + monitoring enabled", c.Name)
		} else {
			missing := []string{}
			if !lg {
				missing = append(missing, "logging")
			}
			if !mn {
				missing = append(missing, "monitoring")
			}
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: missing %s", c.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodepool auto-upgrade ------------------------------------

var CheckGKENPAutoUpgrade = core.Check{
	ID:           "k8s-gke-nodepool-auto-upgrade",
	Title:        "GKE node pools should enable auto-upgrade",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKENodePoolType,
	Description: "Auto-upgrade keeps node pool versions aligned with the " +
		"cluster control plane on the release channel's cadence. Without " +
		"it, the node pool drifts and may exceed the supported skew.",
	Remediation: "`gcloud container node-pools update <np> " +
		"--cluster=<c> --enable-autoupgrade`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC8.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "gke", "nodepool", "upgrade"},
	Scanner: "gke.NPAutoUpgrade",
}

func GKENPAutoUpgrade(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeNPBoolCheck(g, CheckGKENPAutoUpgrade, "auto_upgrade",
		"auto-upgrade enabled", "auto-upgrade disabled"), nil
}

// ----- Nodepool auto-repair -------------------------------------

var CheckGKENPAutoRepair = core.Check{
	ID:           "k8s-gke-nodepool-auto-repair",
	Title:        "GKE node pools should enable auto-repair",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKENodePoolType,
	Description: "Auto-repair detects unhealthy nodes (failed kubelet " +
		"heartbeats, persistent NotReady) and replaces them. Disabling " +
		"it means a failed node sits in the cluster until manual " +
		"intervention.",
	Remediation: "`gcloud container node-pools update <np> " +
		"--cluster=<c> --enable-autorepair`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "gke", "nodepool", "reliability"},
	Scanner: "gke.NPAutoRepair",
}

func GKENPAutoRepair(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeNPBoolCheck(g, CheckGKENPAutoRepair, "auto_repair",
		"auto-repair enabled", "auto-repair disabled"), nil
}

// ----- Nodepool COS image ----------------------------------------

var CheckGKENPCOSImage = core.Check{
	ID:           "k8s-gke-nodepool-cos",
	Title:        "GKE node pools should use Container-Optimized OS",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKENodePoolType,
	Description: "Container-Optimized OS (COS) is Google's hardened, " +
		"minimal node OS. Ubuntu node pools are supported but have a " +
		"larger attack surface and a slower patch cadence than COS.",
	Remediation: "Create node pools with `--image-type=COS_CONTAINERD`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.8"},
		"iso27001": {"A.8.2", "A.8.8"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "gke", "nodepool", "os"},
	Scanner: "gke.NPCOSImage",
}

func GKENPCOSImage(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return gkeNPBoolCheck(g, CheckGKENPCOSImage, "cos_image",
		"COS_CONTAINERD image", "non-COS image"), nil
}

// ----- Nodepool default service account --------------------------

var CheckGKENPDefaultSA = core.Check{
	ID:           "k8s-gke-nodepool-default-sa",
	Title:        "GKE node pools should not use the default Compute Engine SA",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "gke",
	ResourceType: gcpcol.GKENodePoolType,
	Description: "The default Compute Engine SA has the Editor role on " +
		"the project by default. Every node pool using it gives every " +
		"in-cluster workload (and any pod that escapes to the node) " +
		"project-Editor — a serious privilege escalation surface.",
	Remediation: "Create a dedicated minimum-privilege SA for nodes " +
		"(roles/container.nodeServiceAccount + " +
		"roles/monitoring.metricWriter + roles/logging.logWriter). Use " +
		"`--service-account=<sa-email>` on node pool create.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "gke", "nodepool", "iam"},
	Scanner: "gke.NPDefaultSA",
}

func GKENPDefaultSA(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, np := range g.ByType(gcpcol.GKENodePoolType) {
		def, _ := np.Attributes["default_sa"].(bool)
		f := core.Finding{
			CheckID:  CheckGKENPDefaultSA.ID,
			Severity: CheckGKENPDefaultSA.Severity,
			Resource: np.Ref(),
			Tags:     CheckGKENPDefaultSA.Tags,
		}
		if def {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: uses default Compute Engine SA", np.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: dedicated SA", np.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- init -----------------------------------------------------

func init() {
	core.Register(CheckGKEPrivateCluster, GKEPrivateCluster)
	core.Register(CheckGKEMasterAuthorized, GKEMasterAuthorized)
	core.Register(CheckGKEWorkloadIdentity, GKEWorkloadIdentity)
	core.Register(CheckGKEBinaryAuth, GKEBinaryAuth)
	core.Register(CheckGKENetworkPolicy, GKENetworkPolicy)
	core.Register(CheckGKEShieldedNodes, GKEShieldedNodes)
	core.Register(CheckGKEReleaseChannel, GKEReleaseChannel)
	core.Register(CheckGKELegacyABAC, GKELegacyABAC)
	core.Register(CheckGKELoggingMonitoring, GKELoggingMonitoring)
	core.Register(CheckGKENPAutoUpgrade, GKENPAutoUpgrade)
	core.Register(CheckGKENPAutoRepair, GKENPAutoRepair)
	core.Register(CheckGKENPCOSImage, GKENPCOSImage)
	core.Register(CheckGKENPDefaultSA, GKENPDefaultSA)
}

func gkeBoolCheck(g *core.ResourceGraph, check core.Check, attr, passMsg, failMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, c := range g.ByType(gcpcol.GKEClusterType) {
		v, _ := c.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: c.Ref(),
			Tags:     check.Tags,
		}
		if v {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("gke cluster %q: %s", c.Name, passMsg)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("gke cluster %q: %s", c.Name, failMsg)
		}
		findings = append(findings, f)
	}
	return findings
}

func gkeNPBoolCheck(g *core.ResourceGraph, check core.Check, attr, passMsg, failMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, np := range g.ByType(gcpcol.GKENodePoolType) {
		v, _ := np.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: np.Ref(),
			Tags:     check.Tags,
		}
		if v {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: %s", np.Name, passMsg)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: %s", np.Name, failMsg)
		}
		findings = append(findings, f)
	}
	return findings
}
