package k8s

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// DOKS enrichment checks. DOKS resources come from the DO collector
// (provider="digitalocean"); checks register under the kubernetes
// provider.

// ----- HA control plane -----------------------------------------

var CheckDOKSHA = core.Check{
	ID:           "k8s-doks-ha-control-plane",
	Title:        "DOKS clusters should run with HA control plane",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS supports an HA control plane (multiple master " +
		"replicas across zones) for an extra $40/month. Without it, " +
		"control-plane maintenance windows or zone outages cause API " +
		"unavailability. For production workloads, HA is the baseline.",
	Remediation: "`doctl kubernetes cluster update <c> --ha` (creates a " +
		"new HA control plane; existing workloads continue). For new " +
		"clusters, pass `--ha` at create time.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "doks", "ha"},
	Scanner: "doks.HA",
}

func DOKSHA(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return doksBoolCheck(g, CheckDOKSHA, "ha",
		"HA control plane enabled", "single-node control plane (no HA)"), nil
}

// ----- Auto-upgrade ----------------------------------------------

var CheckDOKSAutoUpgrade = core.Check{
	ID:           "k8s-doks-auto-upgrade",
	Title:        "DOKS clusters should enable auto-upgrade",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "Auto-upgrade lets DO promote the cluster within the " +
		"maintenance window when a new minor lands. Without it, the " +
		"cluster sticks at its creation version until manually upgraded " +
		"— and DO unsupports minor versions on a known schedule.",
	Remediation: "`doctl kubernetes cluster update <c> --auto-upgrade`. " +
		"Combine with a maintenance window during low-traffic hours.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "doks", "upgrade"},
	Scanner: "doks.AutoUpgrade",
}

func DOKSAutoUpgrade(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return doksBoolCheck(g, CheckDOKSAutoUpgrade, "auto_upgrade",
		"auto-upgrade enabled", "auto-upgrade disabled"), nil
}

// ----- Surge upgrade ---------------------------------------------

var CheckDOKSSurgeUpgrade = core.Check{
	ID:           "k8s-doks-surge-upgrade",
	Title:        "DOKS clusters should enable surge upgrades",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "Surge upgrades provision replacement nodes before " +
		"draining old ones — workloads stay available across rolling " +
		"node-pool upgrades. Without surge, each upgrade hits a " +
		"capacity dip equal to the node being replaced.",
	Remediation: "`doctl kubernetes cluster update <c> --surge-upgrade=true`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "doks", "upgrade"},
	Scanner: "doks.SurgeUpgrade",
}

func DOKSSurgeUpgrade(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return doksBoolCheck(g, CheckDOKSSurgeUpgrade, "surge_upgrade",
		"surge upgrade enabled", "surge upgrade disabled"), nil
}

// ----- Maintenance window -----------------------------------------

var CheckDOKSMaintenanceWindow = core.Check{
	ID:           "k8s-doks-maintenance-window",
	Title:        "DOKS clusters should configure a maintenance window",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "Without an explicit maintenance window, DO picks one. " +
		"Set the window to low-traffic hours so upgrades, certificate " +
		"rotations, and other maintenance events do not coincide with " +
		"peak load.",
	Remediation: "`doctl kubernetes cluster update <c> " +
		"--maintenance-window=\"sunday 04:00\"` (UTC).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "doks", "upgrade"},
	Scanner: "doks.MaintenanceWindow",
}

func DOKSMaintenanceWindow(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		mw, _ := c.Attributes["maintenance_window"].(string)
		f := core.Finding{
			CheckID:  CheckDOKSMaintenanceWindow.ID,
			Severity: CheckDOKSMaintenanceWindow.Severity,
			Resource: c.Ref(),
			Tags:     CheckDOKSMaintenanceWindow.Tags,
		}
		if mw != "" && mw != " " {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: maintenance window %s", c.Name, mw)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: no maintenance window configured", c.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- VPC attached ----------------------------------------------

var CheckDOKSVPC = core.Check{
	ID:           "k8s-doks-vpc-attached",
	Title:        "DOKS clusters should attach to a non-default VPC",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "DOKS clusters by default land in the region's default " +
		"VPC, which is shared across the account. Attaching to a " +
		"dedicated VPC isolates the cluster's network plane from other " +
		"workloads and makes firewall rules easier to reason about.",
	Remediation: "Create a dedicated VPC: `doctl vpcs create --name=k8s " +
		"--region=<r>`. Recreate the cluster with `--vpc-uuid=<id>` " +
		"(in-place VPC change is not supported).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.4"},
	},
	Tags:    []string{"k8s", "doks", "network"},
	Scanner: "doks.VPC",
}

func DOKSVPC(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		vpc, _ := c.Attributes["vpc_uuid"].(string)
		f := core.Finding{
			CheckID:  CheckDOKSVPC.ID,
			Severity: CheckDOKSVPC.Severity,
			Resource: c.Ref(),
			Tags:     CheckDOKSVPC.Tags,
		}
		if vpc == "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: no VPC attached", c.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: VPC=%s", c.Name, vpc)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Registry integration --------------------------------------

var CheckDOKSRegistry = core.Check{
	ID:           "k8s-doks-registry-integration",
	Title:        "DOKS clusters should integrate with DO Container Registry",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "Enabling registry integration places a dockerconfigjson " +
		"Secret in every namespace, letting workloads pull from the DO " +
		"private Container Registry without manually-managed pull " +
		"credentials. Strict pull credentials beat sprawling " +
		"imagePullSecret literals.",
	Remediation: "`doctl kubernetes cluster registry add <cluster>`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.8.30"},
		"cis-v8":   {"6.8"},
	},
	Tags:    []string{"k8s", "doks", "registry"},
	Scanner: "doks.Registry",
}

func DOKSRegistry(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	return doksBoolCheck(g, CheckDOKSRegistry, "registry_integrated",
		"registry integration enabled", "registry integration disabled"), nil
}

// ----- Cluster active --------------------------------------------

var CheckDOKSActive = core.Check{
	ID:           "k8s-doks-cluster-running",
	Title:        "DOKS clusters should be in running state",
	Severity:     core.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSClusterType,
	Description: "A cluster in degraded / errored / upgrading state needs " +
		"operator attention. running is the steady-state.",
	Remediation: "Check the DO control panel for the failure reason. " +
		"Open a support ticket if the cluster cannot self-heal.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "doks", "reliability"},
	Scanner: "doks.Active",
}

func DOKSActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		status, _ := c.Attributes["status"].(string)
		f := core.Finding{
			CheckID:  CheckDOKSActive.ID,
			Severity: CheckDOKSActive.Severity,
			Resource: c.Ref(),
			Tags:     CheckDOKSActive.Tags,
		}
		if status == "running" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: running", c.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: status=%s", c.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodepool autoscaling --------------------------------------

var CheckDOKSNPAutoScale = core.Check{
	ID:           "k8s-doks-nodepool-autoscale",
	Title:        "DOKS node pools should enable autoscaling",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSNodePoolType,
	Description: "Autoscaling lets the cluster grow under load and " +
		"shrink under idle, matching capacity to demand. Manual " +
		"sizing typically over-provisions for peak or " +
		"under-provisions and trips workloads in surge.",
	Remediation: "`doctl kubernetes cluster node-pool update <c> <np> " +
		"--auto-scale=true --min-nodes=<n> --max-nodes=<n>`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "doks", "nodepool", "autoscale"},
	Scanner: "doks.NPAutoScale",
}

func DOKSNPAutoScale(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, np := range g.ByType(docol.DOKSNodePoolType) {
		as, _ := np.Attributes["auto_scale"].(bool)
		f := core.Finding{
			CheckID:  CheckDOKSNPAutoScale.ID,
			Severity: CheckDOKSNPAutoScale.Severity,
			Resource: np.Ref(),
			Tags:     CheckDOKSNPAutoScale.Tags,
		}
		if as {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: autoscaling enabled", np.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: autoscaling disabled", np.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodepool min nodes -----------------------------------------

var CheckDOKSNPMinNodes = core.Check{
	ID:           "k8s-doks-nodepool-min-nodes",
	Title:        "DOKS node pools should have min_nodes >= 2",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "doks",
	ResourceType: docol.DOKSNodePoolType,
	Description: "Even with autoscaling, a min_nodes of 1 means the " +
		"cluster can drop to a single node — no HA, no rolling update " +
		"headroom, and during a node replacement the cluster has zero " +
		"capacity in that pool.",
	Remediation: "`doctl kubernetes cluster node-pool update <c> <np> " +
		"--min-nodes=2`. For HA workloads, min_nodes >= 3.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "doks", "nodepool", "ha"},
	Scanner: "doks.NPMinNodes",
}

func DOKSNPMinNodes(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, np := range g.ByType(docol.DOKSNodePoolType) {
		minN, _ := np.Attributes["min_nodes"].(int)
		count, _ := np.Attributes["count"].(int)
		// If autoscaling disabled, use count as the effective floor.
		as, _ := np.Attributes["auto_scale"].(bool)
		effective := minN
		if !as {
			effective = count
		}
		f := core.Finding{
			CheckID:  CheckDOKSNPMinNodes.ID,
			Severity: CheckDOKSNPMinNodes.Severity,
			Resource: np.Ref(),
			Tags:     CheckDOKSNPMinNodes.Tags,
		}
		if effective >= 2 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodepool %q: effective floor=%d", np.Name, effective)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodepool %q: effective floor=%d (no HA)", np.Name, effective)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- init -----------------------------------------------------

func init() {
	core.Register(CheckDOKSHA, DOKSHA)
	core.Register(CheckDOKSAutoUpgrade, DOKSAutoUpgrade)
	core.Register(CheckDOKSSurgeUpgrade, DOKSSurgeUpgrade)
	core.Register(CheckDOKSMaintenanceWindow, DOKSMaintenanceWindow)
	core.Register(CheckDOKSVPC, DOKSVPC)
	core.Register(CheckDOKSRegistry, DOKSRegistry)
	core.Register(CheckDOKSActive, DOKSActive)
	core.Register(CheckDOKSNPAutoScale, DOKSNPAutoScale)
	core.Register(CheckDOKSNPMinNodes, DOKSNPMinNodes)
}

func doksBoolCheck(g *core.ResourceGraph, check core.Check, attr, passMsg, failMsg string) []core.Finding {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.DOKSClusterType) {
		v, _ := c.Attributes[attr].(bool)
		f := core.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: c.Ref(),
			Tags:     check.Tags,
		}
		if v {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("doks cluster %q: %s", c.Name, passMsg)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("doks cluster %q: %s", c.Name, failMsg)
		}
		findings = append(findings, f)
	}
	return findings
}
