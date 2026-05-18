package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkDeployment(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":             "default",
		"replicas":              3,
		"ready_replicas":        3,
		"selector_labels":       map[string]string{"app": name},
		"labels":                map[string]string{"app": name},
		"strategy_type":         "RollingUpdate",
		"has_pod_anti_affinity": true,
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.deployment.prod.default." + name,
		Type:       k8scol.DeploymentType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkStatefulSet(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":             "default",
		"replicas":              3,
		"selector_labels":       map[string]string{"app": name},
		"has_pod_anti_affinity": true,
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.statefulset.prod.default." + name,
		Type:       k8scol.StatefulSetType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkDaemonSet(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":               "default",
		"selector_labels":         map[string]string{"app": name},
		"tolerates_control_plane": false,
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.daemonset.prod.default." + name,
		Type:       k8scol.DaemonSetType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func mkPDB(name string, attrs map[string]any) compliancekit.Resource {
	base := map[string]any{
		"namespace":       "default",
		"selector_labels": map[string]string{"app": name},
		"min_available":   "1",
	}
	for k, v := range attrs {
		base[k] = v
	}
	return compliancekit.Resource{
		ID:         "k8s.pdb.prod.default." + name,
		Type:       k8scol.PodDisruptionBudgetType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: base,
	}
}

func TestDeploymentMinReplicas(t *testing.T) {
	g := newPodGraph(
		mkDeployment("ha", map[string]any{"replicas": 3}),
		mkDeployment("single", map[string]any{"replicas": 1}),
	)
	got := runCheck(t, DeploymentMinReplicas, g)
	if got["ha"] != compliancekit.StatusPass || got["single"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestDeploymentRollingUpdate(t *testing.T) {
	g := newPodGraph(
		mkDeployment("good", nil),
		mkDeployment("default-empty", map[string]any{"strategy_type": ""}),
		mkDeployment("recreate", map[string]any{"strategy_type": "Recreate"}),
	)
	got := runCheck(t, DeploymentRollingUpdate, g)
	if got["good"] != compliancekit.StatusPass || got["default-empty"] != compliancekit.StatusPass {
		t.Errorf("good/empty: %v / %v", got["good"], got["default-empty"])
	}
	if got["recreate"] != compliancekit.StatusFail {
		t.Errorf("recreate: %v", got["recreate"])
	}
}

func TestDeploymentPDB(t *testing.T) {
	g := newPodGraph(
		mkDeployment("covered", map[string]any{"selector_labels": map[string]string{"app": "web", "tier": "frontend"}}),
		mkPDB("web-pdb", map[string]any{"selector_labels": map[string]string{"app": "web"}}),
		mkDeployment("uncovered", map[string]any{"selector_labels": map[string]string{"app": "api"}}),
		mkDeployment("single", map[string]any{"replicas": 1, "selector_labels": map[string]string{"app": "x"}}),
	)
	got := runCheck(t, DeploymentPDB, g)
	if got["covered"] != compliancekit.StatusPass {
		t.Errorf("covered: %v", got["covered"])
	}
	if got["uncovered"] != compliancekit.StatusFail {
		t.Errorf("uncovered: %v", got["uncovered"])
	}
	if got["single"] != compliancekit.StatusSkip {
		t.Errorf("single: %v (want skip)", got["single"])
	}
}

func TestStatefulSetPDB(t *testing.T) {
	g := newPodGraph(
		mkStatefulSet("covered", map[string]any{"selector_labels": map[string]string{"app": "db"}}),
		mkPDB("db-pdb", map[string]any{"selector_labels": map[string]string{"app": "db"}}),
		mkStatefulSet("uncovered", map[string]any{"selector_labels": map[string]string{"app": "cache"}}),
	)
	got := runCheck(t, StatefulSetPDB, g)
	if got["covered"] != compliancekit.StatusPass || got["uncovered"] != compliancekit.StatusFail {
		t.Errorf("results: %v", got)
	}
}

func TestDeploymentAntiAffinity(t *testing.T) {
	g := newPodGraph(
		mkDeployment("good", nil),
		mkDeployment("no-affinity", map[string]any{"has_pod_anti_affinity": false}),
		mkDeployment("single", map[string]any{"replicas": 1, "has_pod_anti_affinity": false}),
	)
	got := runCheck(t, DeploymentAntiAffinity, g)
	if got["good"] != compliancekit.StatusPass {
		t.Errorf("good: %v", got["good"])
	}
	if got["no-affinity"] != compliancekit.StatusFail {
		t.Errorf("no-affinity: %v", got["no-affinity"])
	}
	if got["single"] != compliancekit.StatusSkip {
		t.Errorf("single: %v (want skip)", got["single"])
	}
}

func TestDaemonSetControlPlane(t *testing.T) {
	g := newPodGraph(
		mkDaemonSet("app", nil),
		mkDaemonSet("rogue", map[string]any{"tolerates_control_plane": true}),
		mkDaemonSet("cni", map[string]any{"namespace": "kube-system", "tolerates_control_plane": true}),
	)
	got := runCheck(t, DaemonSetControlPlane, g)
	if got["app"] != compliancekit.StatusPass || got["cni"] != compliancekit.StatusPass {
		t.Errorf("app/cni: %v / %v", got["app"], got["cni"])
	}
	if got["rogue"] != compliancekit.StatusFail {
		t.Errorf("rogue: %v", got["rogue"])
	}
}
