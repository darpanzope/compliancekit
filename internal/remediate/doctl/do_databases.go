package doctl

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage database checks.
var legacyDatabasesDoctlEntries = map[string]legacyDoctlEntry{
	"do-db-engine-eol": {risk: remediate.RiskManual,
		content: "# Engine upgrade is operator-driven; plan migration window.\ndoctl databases get DB_ID --format EngineSlug,Version"},
	"do-db-ip-only-trust": {risk: remediate.RiskReview,
		content: "doctl databases firewalls replace DB_ID --rule droplet:DROPLET_ID --rule tag:web"},
	"do-db-no-vpc": {risk: remediate.RiskReview,
		content: "# DB cluster VPC is set at create time; recreate in VPC.\ndoctl databases create new-db --engine pg --size db-s-2vcpu-4gb --region nyc3 --private-network-uuid VPC_UUID"},
	"do-db-single-node": {risk: remediate.RiskReview,
		content: "doctl databases resize DB_ID --num-nodes 3 --size db-s-2vcpu-4gb"},
	"do-db-tls-disabled": {risk: remediate.RiskReview,
		content: "# DO managed DBs accept TLS by default; fix is on consumer side.\ndoctl databases connection DB_ID --format URI\n# Update consumers to ?sslmode=require"},
}

func init() { registerLegacyDoctl(legacyDatabasesDoctlEntries) }
