package k8s

import (
	"testing"

	k8scol "github.com/darpanzope/compliancekit/internal/collectors/k8s"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.21 phase 11 — shared test helpers used by the new spec-driven
// check tests (pods_extra_test.go, reliability_test.go,
// supplychain_test.go, control_plane_test.go, managed_extra_test.go).
//
// The pre-v0.21 test files inline their own resource builders;
// these helpers are scoped to the v0.21 additions to avoid churning
// the older files.

// gph builds a ResourceGraph from a variadic list of resources.
func gph(t *testing.T, rs ...compliancekit.Resource) *compliancekit.ResourceGraph {
	t.Helper()
	g := compliancekit.NewResourceGraph()
	for _, r := range rs {
		g.Add(r)
	}
	return g
}

// mkCluster builds the per-context anchor resource that cluster-
// scoped manual-verify checks emit findings against.
func mkCluster(name string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "k8s.cluster." + name,
		Type:       k8scol.ClusterType,
		Name:       name,
		Provider:   "kubernetes",
		Attributes: map[string]any{},
	}
}
