package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 9 — shared helpers for the per-category legacy backfill
// in this package. Each per-category file declares a legacyBashEntry
// map and calls registerLegacyBash from its init().

type legacyBashEntry struct {
	body   string
	verify string
	notes  string
	risk   remediate.RiskClass
}

func registerLegacyBash(entries map[string]legacyBashEntry) {
	for id, e := range entries {
		e := e
		id := id
		register("bash-legacy-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			s := remediate.Snippet{
				Risk: e.risk, Idempotent: false,
				Content: e.body, VerifyCmd: e.verify, Notes: e.notes,
			}
			if s.Notes == "" {
				s.Notes = fmt.Sprintf("Legacy v0.9 check %q — bespoke bash remediation backfilled in v0.19 phase 9.", id)
			}
			return s, nil
		})
	}
}
