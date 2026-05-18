package remediate_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"

	// Side-effect: register every shipped DO check + every remediation
	// format adapter so the registry the assertions read is fully
	// populated.
	_ "github.com/darpanzope/compliancekit/internal/checks/digitalocean"
	_ "github.com/darpanzope/compliancekit/internal/remediate/bash"
	_ "github.com/darpanzope/compliancekit/internal/remediate/doctl"
	_ "github.com/darpanzope/compliancekit/internal/remediate/terraform"
)

// v0.19 DigitalOcean parity gate.
//
// Definition of done for v0.19 (#19) requires every DO check to ship
// with a bespoke Terraform + doctl + bash remediation strategy. The
// existing wildcard "*" bash fallback in internal/remediate/bash does
// NOT count toward bespoke coverage — operators want a doctl one-liner
// or a TF block, not a "fix manually" stub.
//
// This test enforces a monotonic ratchet on the gap per format. Each
// v0.19 phase that adds a check WITHOUT all three strategies pushes
// the gap up; that fails CI. Each phase that adds a strategy WITHOUT
// the corresponding check pulls the gap down; that fails CI too, so
// the ratchet stays honest. The ceiling shrinks across phases:
//
//	Phase 0 (baseline)             — 68 TF, 68 doctl, 74 bash
//	Phases 1-8 (new check surface) — unchanged (every new check ships
//	                                  with all three formats)
//	Phase 9 (parity backfill)       — 0 / 0 / 0  ← shipped here
//
// At 0 the test is a strict equality gate: every DigitalOcean check
// has bespoke TF + doctl + bash strategies. Any new check that lands
// without all three flips the gate red.
const (
	maxMissingTerraformDO = 0
	maxMissingDoctlDO     = 0
	maxMissingBashDO      = 0
)

func TestParity_DigitalOcean(t *testing.T) {
	var doChecks []compliancekit.Check
	for _, c := range compliancekit.RegisteredChecks() {
		if c.Provider == "digitalocean" {
			doChecks = append(doChecks, c)
		}
	}
	if len(doChecks) == 0 {
		t.Fatal("no digitalocean checks registered — wiring broken or import dropped")
	}

	var missingTF, missingDoctl, missingBash []string
	for _, c := range doChecks {
		formats := bespokeFormatsFor(c.ID)
		if !formats[remediate.FormatTerraform] {
			missingTF = append(missingTF, c.ID)
		}
		if !formats[remediate.FormatDoctl] {
			missingDoctl = append(missingDoctl, c.ID)
		}
		if !formats[remediate.FormatBash] {
			missingBash = append(missingBash, c.ID)
		}
	}
	sort.Strings(missingTF)
	sort.Strings(missingDoctl)
	sort.Strings(missingBash)

	checkRatchet(t, "Terraform", "maxMissingTerraformDO", missingTF, maxMissingTerraformDO)
	checkRatchet(t, "doctl", "maxMissingDoctlDO", missingDoctl, maxMissingDoctlDO)
	checkRatchet(t, "Bash", "maxMissingBashDO", missingBash, maxMissingBashDO)

	t.Logf("DO parity: %d checks total | gaps — TF=%d doctl=%d bash=%d",
		len(doChecks), len(missingTF), len(missingDoctl), len(missingBash))
}

// bespokeFormatsFor returns the set of formats covered by a CONCRETE
// strategy for checkID (i.e. one whose CheckIDs() slice contains the
// exact ID — wildcard "*" strategies are excluded).
//
// Wildcards are excluded because the v0.19 DoD calls for bespoke
// remediations per check, not a one-size-fits-all manual stub.
func bespokeFormatsFor(checkID string) map[remediate.Format]bool {
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

func checkRatchet(t *testing.T, label, constName string, missing []string, ceiling int) {
	t.Helper()
	switch {
	case len(missing) > ceiling:
		t.Errorf("%s parity REGRESSED: %d DO checks lack a bespoke %s strategy (ceiling %d). "+
			"Either add the missing strategies or, if intentional, RAISE %s — but the v0.19 DoD is to drive this to 0.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, strings.Join(missing, "\n  "))
	case len(missing) < ceiling:
		t.Errorf("%s parity IMPROVED past ratchet: %d DO checks lack a bespoke %s strategy "+
			"but ceiling is still %d. Lower %s to %d so future regressions get caught.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, len(missing), strings.Join(missing, "\n  "))
	}
}
