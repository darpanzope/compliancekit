package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 9 — shared helpers for the per-category legacy backfill
// in this package. Each per-category file declares a legacyDoctlEntry
// map and calls registerLegacyDoctl from its init().

type legacyDoctlEntry struct {
	content string
	verify  string
	notes   string
	risk    remediate.RiskClass
}

func registerLegacyDoctl(entries map[string]legacyDoctlEntry) {
	for id, e := range entries {
		e := e
		id := id
		register("doctl-legacy-"+id, []string{id}, func(_ core.Finding) (remediate.Snippet, error) {
			s := remediate.Snippet{
				Risk: e.risk, Idempotent: false,
				Content: e.content, VerifyCmd: e.verify, Notes: e.notes,
			}
			if s.Notes == "" {
				s.Notes = fmt.Sprintf("Legacy v0.9 check %q — bespoke doctl remediation backfilled in v0.19 phase 9.", id)
			}
			return s, nil
		})
	}
}
