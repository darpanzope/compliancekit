package k8s

import (
	"context"
	"fmt"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// minReplicasForHA is the smallest replica count below which a workload
// has no HA story — a single pod can be evicted, a node can fail, a
// rollout will hit zero-instance periods.
const minReplicasForHA = 2

// ----- Deployment min replicas -----------------------------------

var CheckDeploymentMinReplicas = compliancekit.Check{
	ID:           "k8s-deployment-min-replicas",
	Title:        "Deployments should run with at least 2 replicas for HA",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.DeploymentType,
	Description: "A single-replica Deployment has no HA. A node drain, " +
		"a rolling update, or an OOM kill creates a window of zero " +
		"available replicas. Production workloads should run with at " +
		"least two replicas plus a PodDisruptionBudget that keeps one " +
		"available during voluntary disruptions.",
	Remediation: "Set `spec.replicas` to at least 2. For cost-sensitive " +
		"dev/staging Deployments, exclude via a profile or waiver.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14", "A.5.30"},
		"cis-v8":   {"11.2", "12.5"},
	},
	Tags:    []string{"k8s", "controllers", "ha"},
	Scanner: "controllers.DeploymentMinReplicas",
}

func DeploymentMinReplicas(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(k8scol.DeploymentType) {
		replicas, _ := d.Attributes["replicas"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckDeploymentMinReplicas.ID,
			Severity: CheckDeploymentMinReplicas.Severity,
			Resource: d.Ref(),
			Tags:     CheckDeploymentMinReplicas.Tags,
		}
		if replicas >= minReplicasForHA {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("deployment %q: %d replicas", workloadDesc(d), replicas)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("deployment %q: %d replica(s) — no HA", workloadDesc(d), replicas)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Deployment rolling update strategy ------------------------

var CheckDeploymentRollingUpdate = compliancekit.Check{
	ID:           "k8s-deployment-rolling-update",
	Title:        "Deployments should use the RollingUpdate strategy",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.DeploymentType,
	Description: "`strategy.type: Recreate` tears down every existing " +
		"pod before starting new ones, guaranteeing downtime during " +
		"every rollout. RollingUpdate is the safe default for stateless " +
		"workloads; Recreate is correct only when a stateful invariant " +
		"prevents two versions from co-existing.",
	Remediation: "Set `strategy.type: RollingUpdate` and tune " +
		"`rollingUpdate.maxUnavailable` / `maxSurge` based on capacity. " +
		"Keep Recreate only when you have a documented reason.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC8.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.7"},
	},
	Tags:    []string{"k8s", "controllers", "rollout"},
	Scanner: "controllers.DeploymentRollingUpdate",
}

func DeploymentRollingUpdate(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(k8scol.DeploymentType) {
		strategy, _ := d.Attributes["strategy_type"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckDeploymentRollingUpdate.ID,
			Severity: CheckDeploymentRollingUpdate.Severity,
			Resource: d.Ref(),
			Tags:     CheckDeploymentRollingUpdate.Tags,
		}
		// Empty strategy defaults to RollingUpdate per the K8s API.
		if strategy == "" || strategy == "RollingUpdate" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("deployment %q: RollingUpdate strategy", workloadDesc(d))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("deployment %q: strategy=%s (causes downtime)", workloadDesc(d), strategy)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Deployment / StatefulSet PDB missing ----------------------

var CheckDeploymentPDB = compliancekit.Check{
	ID:           "k8s-deployment-pdb-missing",
	Title:        "Multi-replica Deployments should have a PodDisruptionBudget",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.DeploymentType,
	Description: "Without a PodDisruptionBudget, a node drain (cluster " +
		"autoscaler scale-down, kernel patch, cluster upgrade) can " +
		"evict every replica simultaneously. A PDB with " +
		"`minAvailable: 1` or `maxUnavailable: 1` keeps at least one " +
		"replica up across voluntary disruptions.",
	Remediation: "Create a PDB selecting the Deployment's pods: " +
		"`spec.selector` matching the Deployment label and " +
		"`spec.minAvailable: 1`. For 3+ replica workloads, prefer " +
		"`maxUnavailable: 25%` so rollouts are not gated unnecessarily.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14", "A.5.30"},
		"cis-v8":   {"11.2", "12.5"},
	},
	Tags:    []string{"k8s", "controllers", "ha"},
	Scanner: "controllers.DeploymentPDB",
}

func DeploymentPDB(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return controllerPDB(g, CheckDeploymentPDB, k8scol.DeploymentType, "deployment"), nil
}

var CheckStatefulSetPDB = compliancekit.Check{
	ID:           "k8s-statefulset-pdb-missing",
	Title:        "Multi-replica StatefulSets should have a PodDisruptionBudget",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.StatefulSetType,
	Description: "StatefulSets carry persistent state, so simultaneous " +
		"eviction is even more disruptive than for Deployments. A PDB " +
		"with `minAvailable: <replicas-1>` keeps quorum across node " +
		"drains and rolling cluster upgrades.",
	Remediation: "Create a PDB selecting the StatefulSet's pods. For " +
		"quorum-based services (etcd, ZooKeeper, Postgres replicas) " +
		"set `minAvailable` to N-1 where N is replicas.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14", "A.5.30"},
		"cis-v8":   {"11.2", "12.5"},
	},
	Tags:    []string{"k8s", "controllers", "ha", "stateful"},
	Scanner: "controllers.StatefulSetPDB",
}

func StatefulSetPDB(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return controllerPDB(g, CheckStatefulSetPDB, k8scol.StatefulSetType, "statefulset"), nil
}

// controllerPDB is the shared PDB-coverage check for Deployments and
// StatefulSets. It looks for any PDB in the same namespace whose
// selector is a subset of the controller's selector — that's how the
// Kubernetes API decides which pods a PDB protects.
func controllerPDB(g *compliancekit.ResourceGraph, check compliancekit.Check, controllerType, label string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
	pdbsByNs := indexPDBs(g)

	for _, ctrl := range g.ByType(controllerType) {
		replicas, _ := ctrl.Attributes["replicas"].(int)
		ns, _ := ctrl.Attributes["namespace"].(string)
		f := compliancekit.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: ctrl.Ref(),
			Tags:     check.Tags,
		}
		if replicas < minReplicasForHA {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("%s %q: single replica, PDB not applicable", label, workloadDesc(ctrl))
			findings = append(findings, f)
			continue
		}
		ctrlLabels, _ := ctrl.Attributes["selector_labels"].(map[string]string)
		covered := pdbCovers(pdbsByNs[ns], ctrlLabels)
		if covered {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("%s %q: PDB covers selector", label, workloadDesc(ctrl))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("%s %q: %d replicas, no PDB protects the selector", label, workloadDesc(ctrl), replicas)
		}
		findings = append(findings, f)
	}
	return findings
}

func indexPDBs(g *compliancekit.ResourceGraph) map[string][]compliancekit.Resource {
	out := map[string][]compliancekit.Resource{}
	for _, p := range g.ByType(k8scol.PodDisruptionBudgetType) {
		ns, _ := p.Attributes["namespace"].(string)
		out[ns] = append(out[ns], p)
	}
	return out
}

// pdbCovers reports whether any PDB in pdbs has a selector that is a
// subset of ctrlLabels. The K8s API requires the PDB selector to match
// the controller's pods, which means every (k, v) on the PDB must
// appear on the controller labels.
func pdbCovers(pdbs []compliancekit.Resource, ctrlLabels map[string]string) bool {
	if len(ctrlLabels) == 0 {
		return false
	}
	for _, p := range pdbs {
		pdbSel, _ := p.Attributes["selector_labels"].(map[string]string)
		if len(pdbSel) == 0 {
			continue
		}
		if labelsSubset(pdbSel, ctrlLabels) {
			return true
		}
	}
	return false
}

func labelsSubset(sub, super map[string]string) bool {
	for k, v := range sub {
		if super[k] != v {
			return false
		}
	}
	return true
}

// ----- Deployment anti-affinity ----------------------------------

var CheckDeploymentAntiAffinity = compliancekit.Check{
	ID:           "k8s-deployment-anti-affinity",
	Title:        "Multi-replica Deployments should set podAntiAffinity",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.DeploymentType,
	Description: "Two replicas on the same node give the appearance of " +
		"HA without the reality — a single node failure takes both down. " +
		"`podAntiAffinity` (preferred or required) spreads replicas " +
		"across nodes (or AZs, with topology spread) and is the standard " +
		"way to get genuine fault tolerance.",
	Remediation: "Add `affinity.podAntiAffinity` to the pod template. " +
		"`preferredDuringSchedulingIgnoredDuringExecution` with " +
		"`topologyKey: kubernetes.io/hostname` is the right default; " +
		"upgrade to `required` for critical workloads.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "A1.2"},
		"iso27001": {"A.8.14", "A.5.30"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"k8s", "controllers", "ha"},
	Scanner: "controllers.DeploymentAntiAffinity",
}

func DeploymentAntiAffinity(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(k8scol.DeploymentType) {
		replicas, _ := d.Attributes["replicas"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckDeploymentAntiAffinity.ID,
			Severity: CheckDeploymentAntiAffinity.Severity,
			Resource: d.Ref(),
			Tags:     CheckDeploymentAntiAffinity.Tags,
		}
		if replicas < minReplicasForHA {
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("deployment %q: single replica, anti-affinity not applicable", workloadDesc(d))
			findings = append(findings, f)
			continue
		}
		has, _ := d.Attributes["has_pod_anti_affinity"].(bool)
		if has {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("deployment %q: podAntiAffinity configured", workloadDesc(d))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("deployment %q: %d replicas without podAntiAffinity (single-node failure risk)", workloadDesc(d), replicas)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- DaemonSet control-plane tolerance -------------------------

var CheckDaemonSetControlPlane = compliancekit.Check{
	ID:           "k8s-daemonset-control-plane-tolerance",
	Title:        "Non-system DaemonSets should not tolerate control-plane taints",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "controllers",
	ResourceType: k8scol.DaemonSetType,
	Description: "Tolerating `node-role.kubernetes.io/control-plane` " +
		"lets the DaemonSet schedule pods on master nodes. That is " +
		"correct for cluster-critical workloads (CNI agents, log " +
		"forwarders, node-exporter). For application DaemonSets it is " +
		"a posture failure: a compromise of the DS pod becomes a " +
		"control-plane compromise.",
	Remediation: "Remove the control-plane toleration unless the DS is " +
		"genuinely cluster-infrastructure. Use namespaces or labels to " +
		"distinguish infra from workload DaemonSets in policy.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.5.15"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "controllers", "control-plane"},
	Scanner: "controllers.DaemonSetControlPlane",
}

func DaemonSetControlPlane(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(k8scol.DaemonSetType) {
		tolerates, _ := d.Attributes["tolerates_control_plane"].(bool)
		ns, _ := d.Attributes["namespace"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckDaemonSetControlPlane.ID,
			Severity: CheckDaemonSetControlPlane.Severity,
			Resource: d.Ref(),
			Tags:     CheckDaemonSetControlPlane.Tags,
		}
		if !tolerates {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("daemonset %q: does not tolerate control-plane taint", workloadDesc(d))
			findings = append(findings, f)
			continue
		}
		// Allow infra namespaces.
		if isSystemNamespace(ns) {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("daemonset %q: tolerates control-plane (system namespace)", workloadDesc(d))
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("daemonset %q: tolerates control-plane taint outside a system namespace", workloadDesc(d))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

// ----- helpers + init --------------------------------------------

func init() {
	compliancekit.Register(CheckDeploymentMinReplicas, DeploymentMinReplicas)
	compliancekit.Register(CheckDeploymentRollingUpdate, DeploymentRollingUpdate)
	compliancekit.Register(CheckDeploymentPDB, DeploymentPDB)
	compliancekit.Register(CheckStatefulSetPDB, StatefulSetPDB)
	compliancekit.Register(CheckDeploymentAntiAffinity, DeploymentAntiAffinity)
	compliancekit.Register(CheckDaemonSetControlPlane, DaemonSetControlPlane)
}

// workloadDesc renders "ns/name" for finding messages on any namespaced
// workload resource.
func workloadDesc(r compliancekit.Resource) string {
	ns, _ := r.Attributes["namespace"].(string)
	if ns == "" {
		return r.Name
	}
	return ns + "/" + r.Name
}
