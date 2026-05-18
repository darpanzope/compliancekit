package k8s

import (
	"context"
	"fmt"
	"strings"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

const nodeOldAgeDays = 365

// ----- Node Ready ------------------------------------------------

var CheckNodeReady = compliancekit.Check{
	ID:           "k8s-node-not-ready",
	Title:        "Nodes should be in Ready state",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "A NotReady node still consumes cluster capacity (pods " +
		"are scheduled to it before the condition flips) but cannot " +
		"actually run workloads. Investigate: kubelet down, network " +
		"partition, disk full, kernel deadlock.",
	Remediation: "`kubectl describe node <name>` for the failing " +
		"condition. Common fixes: restart kubelet, free disk space, " +
		"reboot the node.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "nodes", "reliability"},
	Scanner: "nodes.NodeReady",
}

func NodeReady(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return nodeConditionCheck(g, CheckNodeReady, "Ready", "True", false), nil
}

// ----- Pressure conditions ---------------------------------------

var CheckNodeDiskPressure = compliancekit.Check{
	ID:           "k8s-node-disk-pressure",
	Title:        "Nodes should not report DiskPressure",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "DiskPressure indicates the node's image filesystem or " +
		"root filesystem is filling up. Once eviction thresholds are " +
		"crossed, the kubelet kills pods to reclaim space — typically " +
		"hitting the largest-image workloads first.",
	Remediation: "Clean unused images (`crictl rmi`), bump the node's " +
		"disk size, or migrate workloads to a larger instance type.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "nodes", "pressure"},
	Scanner: "nodes.NodeDiskPressure",
}

func NodeDiskPressure(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return nodeConditionCheck(g, CheckNodeDiskPressure, "DiskPressure", "False", true), nil
}

var CheckNodeMemoryPressure = compliancekit.Check{
	ID:           "k8s-node-memory-pressure",
	Title:        "Nodes should not report MemoryPressure",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "MemoryPressure means the kubelet is about to start " +
		"evicting pods to free memory. Persistent pressure indicates " +
		"either overcommit or an OOM-prone workload.",
	Remediation: "Lower pod memory requests, scale down per-node " +
		"density, or move to a larger instance type.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "nodes", "pressure"},
	Scanner: "nodes.NodeMemoryPressure",
}

func NodeMemoryPressure(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return nodeConditionCheck(g, CheckNodeMemoryPressure, "MemoryPressure", "False", true), nil
}

var CheckNodePIDPressure = compliancekit.Check{
	ID:           "k8s-node-pid-pressure",
	Title:        "Nodes should not report PIDPressure",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "PIDPressure indicates the node is running out of " +
		"process IDs. This is rare in modern setups but can be " +
		"triggered by fork-bomb workloads or processes leaking threads.",
	Remediation: "Identify the offending workload via `kubectl top pod " +
		"--all-namespaces --sort-by=cpu` and the per-pod process " +
		"count. Cap with `pids` ResourceQuota or scale.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "nodes", "pressure"},
	Scanner: "nodes.NodePIDPressure",
}

func NodePIDPressure(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return nodeConditionCheck(g, CheckNodePIDPressure, "PIDPressure", "False", true), nil
}

// ----- Node Unschedulable ----------------------------------------

var CheckNodeUnschedulable = compliancekit.Check{
	ID:           "k8s-node-unschedulable",
	Title:        "Nodes should not stay cordoned indefinitely",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "A node with `spec.unschedulable: true` (cordoned) is " +
		"intentionally taken out of rotation — typical during draining " +
		"for upgrades or hardware replacement. A node stuck cordoned " +
		"is usually a forgotten maintenance window.",
	Remediation: "`kubectl uncordon <name>` to put it back into " +
		"rotation, or `kubectl delete node <name>` if it was truly " +
		"removed.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "nodes", "hygiene"},
	Scanner: "nodes.NodeUnschedulable",
}

func NodeUnschedulable(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		unsched, _ := n.Attributes["unschedulable"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckNodeUnschedulable.ID,
			Severity: CheckNodeUnschedulable.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeUnschedulable.Tags,
		}
		if unsched {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: cordoned", n.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: schedulable", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Container runtime -----------------------------------------

var CheckNodeContainerRuntime = compliancekit.Check{
	ID:           "k8s-node-container-runtime",
	Title:        "Nodes should use containerd or cri-o, not dockershim",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "Dockershim was removed in K8s 1.24 (2022). Any node " +
		"still showing a `docker://` runtime is running an unsupported " +
		"kubelet build. containerd is the modern default; cri-o is the " +
		"Red Hat-blessed alternative.",
	Remediation: "Upgrade the kubelet / node image to one shipping " +
		"containerd. For managed K8s (EKS/GKE/AKS/DOKS), select a " +
		"containerd node group / image type.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC8.1"},
		"iso27001": {"A.8.8", "A.8.32"},
		"cis-v8":   {"4.1", "7.4"},
	},
	Tags:    []string{"k8s", "nodes", "runtime"},
	Scanner: "nodes.NodeContainerRuntime",
}

func NodeContainerRuntime(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		rt, _ := n.Attributes["container_runtime"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckNodeContainerRuntime.ID,
			Severity: CheckNodeContainerRuntime.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeContainerRuntime.Tags,
		}
		switch {
		case strings.HasPrefix(rt, "containerd://"), strings.HasPrefix(rt, "cri-o://"):
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: runtime=%s", n.Name, rt)
		case strings.HasPrefix(rt, "docker://"):
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: runtime=%s (dockershim removed in K8s 1.24)", n.Name, rt)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: runtime=%s (unrecognized)", n.Name, rt)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Node OS image age -----------------------------------------

var CheckNodeOSImageAge = compliancekit.Check{
	ID:           "k8s-node-old-image",
	Title:        "Nodes should be replaced within 1 year of creation",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "Long-lived nodes accumulate kernel CVEs and miss " +
		"image-level improvements (containerd version, kubelet bug " +
		"fixes). Best practice: rotate nodes through replacement on a " +
		"schedule (managed K8s does this automatically when auto-" +
		"upgrade is enabled).",
	Remediation: "For managed K8s, enable node auto-upgrade. For self-" +
		"managed, schedule periodic image rebuilds and rolling node " +
		"replacement.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC8.1"},
		"iso27001": {"A.8.8", "A.8.32"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "nodes", "patching"},
	Scanner: "nodes.NodeOSImageAge",
}

func NodeOSImageAge(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		age, _ := n.Attributes["age_days"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckNodeOSImageAge.ID,
			Severity: CheckNodeOSImageAge.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeOSImageAge.Tags,
		}
		if age > nodeOldAgeDays {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: %d days old (> %d)", n.Name, age, nodeOldAgeDays)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: %d days old", n.Name, age)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Node zone label -------------------------------------------

var CheckNodeZoneLabel = compliancekit.Check{
	ID:           "k8s-node-zone-label",
	Title:        "Worker nodes should carry topology.kubernetes.io/zone",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "Topology-aware scheduling (`topologyKey: topology." +
		"kubernetes.io/zone`) lets controllers spread replicas across " +
		"availability zones. Without the standard label set, the " +
		"primitive is unavailable and pod anti-affinity falls back to " +
		"hostname-only spread.",
	Remediation: "Most cloud-provider cluster controllers set this " +
		"automatically. If self-managed, label nodes: `kubectl label " +
		"node <name> topology.kubernetes.io/zone=us-east-1a`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "nodes", "topology"},
	Scanner: "nodes.NodeZoneLabel",
}

func NodeZoneLabel(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		// Skip control-plane nodes — they don't always carry zone
		// labels in self-managed setups.
		if isCP, _ := n.Attributes["is_control_plane"].(bool); isCP {
			continue
		}
		has, _ := n.Attributes["has_zone_label"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckNodeZoneLabel.ID,
			Severity: CheckNodeZoneLabel.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeZoneLabel.Tags,
		}
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: zone label set", n.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: no zone label (topology-aware scheduling unavailable)", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Node region label -----------------------------------------

var CheckNodeRegionLabel = compliancekit.Check{
	ID:           "k8s-node-region-label",
	Title:        "Worker nodes should carry topology.kubernetes.io/region",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "Multi-region clusters use the region label to scope " +
		"workloads to specific cloud regions. Single-region clusters " +
		"still benefit by being explicit; tooling that consumes " +
		"topology labels (e.g. topology-aware service routing) " +
		"requires it.",
	Remediation: "Most cloud controllers set this automatically. " +
		"`kubectl label node <name> " +
		"topology.kubernetes.io/region=us-east-1`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "nodes", "topology"},
	Scanner: "nodes.NodeRegionLabel",
}

func NodeRegionLabel(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		if isCP, _ := n.Attributes["is_control_plane"].(bool); isCP {
			continue
		}
		has, _ := n.Attributes["has_region_label"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckNodeRegionLabel.ID,
			Severity: CheckNodeRegionLabel.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeRegionLabel.Tags,
		}
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: region label set", n.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: no region label", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Node taints control plane --------------------------------

var CheckNodeCPTaint = compliancekit.Check{
	ID:           "k8s-node-control-plane-taint",
	Title:        "Control-plane nodes should carry NoSchedule taint",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "nodes",
	ResourceType: k8scol.NodeType,
	Description: "Without the standard `node-role.kubernetes.io/control-" +
		"plane:NoSchedule` taint, application pods can land on master " +
		"nodes alongside the API server, controllers, and etcd. A " +
		"workload OOM-killing kube-apiserver is the textbook way to " +
		"brick a cluster.",
	Remediation: "`kubectl taint node <name> " +
		"node-role.kubernetes.io/control-plane=:NoSchedule`. For " +
		"managed clusters this is set automatically; only flag self-" +
		"managed setups missing the taint.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC7.3"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "nodes", "control-plane"},
	Scanner: "nodes.NodeCPTaint",
}

func NodeCPTaint(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		isCP, _ := n.Attributes["is_control_plane"].(bool)
		if !isCP {
			continue
		}
		taints, _ := n.Attributes["taints"].([]map[string]string)
		hasTaint := false
		for _, t := range taints {
			if (t["key"] == "node-role.kubernetes.io/control-plane" || t["key"] == "node-role.kubernetes.io/master") &&
				t["effect"] == "NoSchedule" {
				hasTaint = true
				break
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckNodeCPTaint.ID,
			Severity: CheckNodeCPTaint.Severity,
			Resource: n.Ref(),
			Tags:     CheckNodeCPTaint.Tags,
		}
		if hasTaint {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: control-plane NoSchedule taint set", n.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: control-plane without NoSchedule taint", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- init -----------------------------------------------------

func init() {
	compliancekit.Register(CheckNodeReady, NodeReady)
	compliancekit.Register(CheckNodeDiskPressure, NodeDiskPressure)
	compliancekit.Register(CheckNodeMemoryPressure, NodeMemoryPressure)
	compliancekit.Register(CheckNodePIDPressure, NodePIDPressure)
	compliancekit.Register(CheckNodeUnschedulable, NodeUnschedulable)
	compliancekit.Register(CheckNodeContainerRuntime, NodeContainerRuntime)
	compliancekit.Register(CheckNodeOSImageAge, NodeOSImageAge)
	compliancekit.Register(CheckNodeZoneLabel, NodeZoneLabel)
	compliancekit.Register(CheckNodeRegionLabel, NodeRegionLabel)
	compliancekit.Register(CheckNodeCPTaint, NodeCPTaint)
}

// nodeConditionCheck flags nodes whose named condition does not equal
// the expected value. inverted=true means "Fail when condition value
// is `True` (presence indicates badness)."
func nodeConditionCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, condName, expected string, inverted bool) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(k8scol.NodeType) {
		conds, _ := n.Attributes["conditions"].(map[string]string)
		val := conds[condName]
		f := compliancekit.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: n.Ref(),
			Tags:     check.Tags,
		}
		pass := val == expected
		if inverted {
			pass = val != "True"
		}
		if pass {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("node %q: %s=%s", n.Name, condName, val)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("node %q: %s=%s", n.Name, condName, val)
		}
		findings = append(findings, f)
	}
	return findings
}
