package remediate_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"

	// Side-effect imports register every shipped K8s check and every
	// remediation format adapter so the assertions read a fully-
	// populated registry.
	_ "github.com/darpanzope/compliancekit/internal/checks/k8s"
	_ "github.com/darpanzope/compliancekit/internal/remediate/bash"
	_ "github.com/darpanzope/compliancekit/internal/remediate/helm"
	_ "github.com/darpanzope/compliancekit/internal/remediate/kubectl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/terraform"
)

// v0.21 Kubernetes parity gate.
//
// Per ROADMAP § v0.21: every K8s check (provider="kubernetes") ships
// with a bespoke kubectl remediation strategy. Helm + Terraform are
// added per-check ONLY where they are the natural fit (Helm for
// chart-deployable workloads, TF for cluster-shape resources like
// DOKS/EKS/GKE control plane + node pools) and are NOT gated by this
// test — see https://github.com/darpanzope/compliancekit/issues/21 for
// the rationale (most K8s findings — RBAC, secrets, pod-security on
// running pods — are not naturally Helm-shaped).
//
// Bash coverage is provided by the wildcard fallback in
// internal/remediate/bash for any check that doesn't ship a bespoke
// strategy, so the operator-team copy-paste workflow stays covered
// even when this ratchet flags a kubectl miss.
//
// Same ratchet shape as TestParity_DigitalOcean / TestParity_Linux:
//
//   - len(missing) > ceiling → PARITY REGRESSED (a new K8s check
//     landed without a bespoke kubectl strategy).
//   - len(missing) < ceiling → ratchet stale (lower the constant).
//
// Phase rollout:
//
//	Phase 0  (baseline)            — count measured at v0.21 entry
//	Phases 1-9 (new check surface) — stays flat (every new check
//	                                  lands with a kubectl strategy)
//	Phase 10 (parity backfill)     — drove to 0 (strict equality gate)
//
// At 0 the test is a strict equality gate — a single K8s check
// shipped without a bespoke kubectl strategy will fail pre-commit.
const maxMissingKubectlK8s = 0

func TestParity_Kubernetes(t *testing.T) {
	var k8sChecks []core.Check
	for _, c := range core.RegisteredChecks() {
		if c.Provider == "kubernetes" {
			k8sChecks = append(k8sChecks, c)
		}
	}
	if len(k8sChecks) == 0 {
		t.Fatal("no kubernetes checks registered — wiring broken or import dropped")
	}

	var missingKubectl []string
	for _, c := range k8sChecks {
		formats := bespokeFormatsForK8s(c.ID)
		if !formats[remediate.FormatKubectl] {
			missingKubectl = append(missingKubectl, c.ID)
		}
	}
	sort.Strings(missingKubectl)

	checkK8sRatchet(t, "Kubectl", "maxMissingKubectlK8s", missingKubectl, maxMissingKubectlK8s)

	t.Logf("Kubernetes parity: %d checks total | kubectl gap %d",
		len(k8sChecks), len(missingKubectl))
}

// bespokeFormatsForK8s returns the set of formats covered by a
// CONCRETE strategy for checkID (wildcard "*" strategies excluded —
// the bash package ships a wildcard fallback that doesn't count
// toward bespoke coverage).
func bespokeFormatsForK8s(checkID string) map[remediate.Format]bool {
	out := map[remediate.Format]bool{}
	for _, s := range remediate.Default.StrategiesFor(checkID) {
		bespoke := false
		for _, id := range s.CheckIDs() {
			if id == checkID {
				bespoke = true
				break
			}
		}
		if !bespoke {
			continue
		}
		for _, f := range s.Formats() {
			out[f] = true
		}
	}
	return out
}

func checkK8sRatchet(t *testing.T, label, constName string, missing []string, ceiling int) {
	t.Helper()
	switch {
	case len(missing) > ceiling:
		t.Errorf("%s parity REGRESSED: %d K8s checks lack a bespoke %s strategy (ceiling %d). "+
			"Either add the missing strategy or raise %s — but the v0.21 DoD is to drive this to 0.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, strings.Join(missing, "\n  "))
	case len(missing) < ceiling:
		t.Errorf("%s parity IMPROVED past ratchet: %d K8s checks lack a bespoke %s strategy "+
			"but ceiling is still %d. Lower %s to %d so future regressions get caught.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, len(missing), strings.Join(missing, "\n  "))
	}
}
