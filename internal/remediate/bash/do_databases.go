package bash

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage database checks.
var legacyDatabasesBashEntries = map[string]legacyBashEntry{
	"do-db-engine-eol":               {risk: remediate.RiskManual, body: "echo 'plan engine upgrade window: doctl databases get DB_ID --format EngineSlug,Version' >&2"},
	"do-db-firewall-includes-public": {risk: remediate.RiskReview, body: "doctl databases firewalls replace DB_ID --rule droplet:DROPLET_ID"},
	"do-db-ip-only-trust":            {risk: remediate.RiskReview, body: "doctl databases firewalls replace DB_ID --rule droplet:DROPLET_ID --rule tag:web"},
	"do-db-no-firewall-rules":        {risk: remediate.RiskReview, body: "doctl databases firewalls append DB_ID --rule droplet:DROPLET_ID"},
	"do-db-no-maintenance-window":    {risk: remediate.RiskSafe, body: "doctl databases maintenance-window update DB_ID --day sunday --hour 04:00:00"},
	"do-db-no-vpc":                   {risk: remediate.RiskReview, body: "echo 'DB cluster VPC is set at create; recreate cluster in VPC' >&2"},
	"do-db-single-node":              {risk: remediate.RiskReview, body: "doctl databases resize DB_ID --num-nodes 3 --size db-s-2vcpu-4gb"},
	"do-db-tls-disabled":             {risk: remediate.RiskReview, body: "doctl databases connection DB_ID --format URI\n# Update consumers to ?sslmode=require"},
}

func init() { registerLegacyBash(legacyDatabasesBashEntries) }
