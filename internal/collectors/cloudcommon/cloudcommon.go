// Package cloudcommon contains the cross-cloud abstractions every
// cloud collector reuses: account/region resource attribution helpers,
// the per-cloud Resource ID convention, and the per-cloud Region
// listing protocol.
//
// Established at v0.7 alongside AWS. v0.8 (GCP), v0.10 (Hetzner), and
// the v1.7 tail clouds (Cloudflare, GitHub, Workspace, Vercel, Linode,
// Vultr) plug into the same surface.
//
// This package is deliberately tiny -- abstractions only earn their
// keep when they prevent real duplication, so cloudcommon stays at
// the level of "the three attributes every cloud resource has."
// Provider-specific helpers stay in the per-provider collector
// packages.
package cloudcommon

import (
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// Account-attribution attribute keys. Set these on every cloud
// resource so the evidence pack's control-mapping.csv carries
// unambiguous identity across multi-account / multi-project /
// multi-region fleets.
//
// At v0.7 these are the AWS-shaped names. Other providers reuse:
//
//	GCP        -> AttrAccountID = "<project-id>", AttrRegion = "<location>"
//	Hetzner    -> AttrAccountID = "<project-name>", AttrRegion empty
//	K8s        -> AttrAccountID = "<context-name>", AttrRegion empty
//
// The semantic is "owning account / region" -- the field where the
// resource bills, not the field where the API call was issued.
const (
	AttrAccountID = "account_id"
	AttrRegion    = "region"
)

// ResourceCoord is the (account, region) tuple every cloud resource
// carries. Helpers below use it so the per-collector code does not
// repeat the field names.
type ResourceCoord struct {
	AccountID string
	Region    string
}

// Stamp sets AttrAccountID and AttrRegion on r. Idempotent: calling
// Stamp twice with the same coord produces the same Resource. Empty
// strings are skipped so a collector that does not know one or both
// fields (e.g. a per-region scan that hasn't resolved the account
// yet) does not write empty values.
func Stamp(r *compliancekit.Resource, coord ResourceCoord) {
	if r.Attributes == nil {
		r.Attributes = map[string]any{}
	}
	if coord.AccountID != "" {
		r.Attributes[AttrAccountID] = coord.AccountID
	}
	if coord.Region != "" {
		r.Attributes[AttrRegion] = coord.Region
		// Resource.Region is the typed shorthand; keep both in sync
		// so a check author can read either.
		r.Region = coord.Region
	}
}

// CoordOf reads the (account, region) coord back from r. Returns a
// zero-valued ResourceCoord if either attribute is absent. The check
// renderer + evidence-pack writer use this to populate the
// control-mapping.csv account_id / region columns.
func CoordOf(r compliancekit.Resource) ResourceCoord {
	c := ResourceCoord{Region: r.Region}
	if c.Region == "" {
		if s, ok := r.Attributes[AttrRegion].(string); ok {
			c.Region = s
		}
	}
	if s, ok := r.Attributes[AttrAccountID].(string); ok {
		c.AccountID = s
	}
	return c
}
