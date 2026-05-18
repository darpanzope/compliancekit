package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 9 — shared helpers for the per-category legacy backfill
// files (do_account.go, do_apps.go, ..., do_databases.go, do_droplets.go,
// do_compute.go). Each per-category file declares a legacyTFEntry map
// of {checkID → snippet shape} and calls registerLegacyTF from its
// init() block.
//
// The split keeps the legacy backfill living alongside the v0.19
// bespoke strategies for the same DigitalOcean surface, rather than
// in a single 200-entry catch-all file.

type legacyTFEntry struct {
	content string
	notes   string
	risk    remediate.RiskClass
	refs    []string
}

const tfLegacyHintHeader = "# v0.19 backfill — paste into your TF root module and `terraform plan`.\n"

// registerLegacyTF wires the entries from a per-category map into the
// package registry under names of the shape "tf-legacy-<checkID>".
func registerLegacyTF(entries map[string]legacyTFEntry) {
	for id, e := range entries {
		e := e
		id := id
		register("tf-legacy-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			s := remediate.Snippet{
				Risk: e.risk, Idempotent: true,
				Content: tfLegacyHintHeader + e.content,
				Notes:   e.notes,
				Refs:    e.refs,
			}
			if s.Notes == "" {
				s.Notes = fmt.Sprintf("Legacy v0.9 check %q — bespoke Terraform remediation backfilled in v0.19 phase 9.", id)
			}
			return s, nil
		})
	}
}
