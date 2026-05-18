package remediate_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"

	// Side-effect imports register every shipped Linux check and
	// every remediation format adapter into the registries the
	// assertions read.
	_ "github.com/darpanzope/compliancekit/internal/checks/linux"
	_ "github.com/darpanzope/compliancekit/internal/remediate/ansible"
	_ "github.com/darpanzope/compliancekit/internal/remediate/bash"
)

// v0.20 Linux parity gate.
//
// Per ROADMAP § v0.20: every Linux check ships with bespoke bash +
// Ansible remediation. Terraform is excluded — system-hardening
// findings (sshd config / sysctl / mount options / auditd rules)
// don't have a clean TF expression and would be ceremony with no
// payoff. The two formats Linux operators reach for are the shell
// (`ssh root@host bash`) and Ansible (`ansible-playbook -l hosts`).
//
// Same ratchet shape as TestParity_DigitalOcean:
//
//   - len(missing) > ceiling → PARITY REGRESSED (a new Linux check
//     landed without all two formats).
//   - len(missing) < ceiling → ratchet stale (lower the constant).
//
// Phase rollout:
//
//	Phase 0 (baseline)             — counts measured at v0.20 entry
//	Phases 2-9 (new check surface) — stays flat (every new check
//	                                  lands with bash + Ansible)
//	Phase 10 (parity backfill)     — drove both to 0 (strict equality gate)
//
// Both ceilings are 0. A single Linux check shipped without a bespoke
// bash + Ansible strategy will fail this test.
const (
	maxMissingAnsibleLinux = 0
	maxMissingBashLinux    = 0
)

func TestParity_Linux(t *testing.T) {
	var linuxChecks []compliancekit.Check
	for _, c := range compliancekit.RegisteredChecks() {
		if c.Provider == "linux" {
			linuxChecks = append(linuxChecks, c)
		}
	}
	if len(linuxChecks) == 0 {
		t.Fatal("no linux checks registered — wiring broken or import dropped")
	}

	var missingAnsible, missingBash []string
	for _, c := range linuxChecks {
		formats := bespokeFormatsForLinux(c.ID)
		if !formats[remediate.FormatAnsible] {
			missingAnsible = append(missingAnsible, c.ID)
		}
		if !formats[remediate.FormatBash] {
			missingBash = append(missingBash, c.ID)
		}
	}
	sort.Strings(missingAnsible)
	sort.Strings(missingBash)

	checkLinuxRatchet(t, "Ansible", "maxMissingAnsibleLinux", missingAnsible, maxMissingAnsibleLinux)
	checkLinuxRatchet(t, "Bash", "maxMissingBashLinux", missingBash, maxMissingBashLinux)

	t.Logf("Linux parity: %d checks total | gaps — ansible=%d bash=%d",
		len(linuxChecks), len(missingAnsible), len(missingBash))
}

// bespokeFormatsForLinux returns the set of formats covered by a
// CONCRETE strategy for checkID (wildcard "*" strategies excluded —
// the bash package ships a wildcard fallback that doesn't count
// toward bespoke coverage).
func bespokeFormatsForLinux(checkID string) map[remediate.Format]bool {
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

func checkLinuxRatchet(t *testing.T, label, constName string, missing []string, ceiling int) {
	t.Helper()
	switch {
	case len(missing) > ceiling:
		t.Errorf("%s parity REGRESSED: %d Linux checks lack a bespoke %s strategy (ceiling %d). "+
			"Either add the missing strategies or raise %s — but the v0.20 DoD is to drive this to 0.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, strings.Join(missing, "\n  "))
	case len(missing) < ceiling:
		t.Errorf("%s parity IMPROVED past ratchet: %d Linux checks lack a bespoke %s strategy "+
			"but ceiling is still %d. Lower %s to %d so future regressions get caught.\nMissing:\n  %s",
			label, len(missing), label, ceiling, constName, len(missing), strings.Join(missing, "\n  "))
	}
}
