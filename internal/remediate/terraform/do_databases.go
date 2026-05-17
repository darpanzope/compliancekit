package terraform

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage managed-database
// checks. (No v0.19 bespoke database strategies; this file is
// backfill-only for now. Add new strategies here as the surface
// grows.)

var legacyDatabasesTFEntries = map[string]legacyTFEntry{
	"do-db-engine-eol": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_database_cluster\" \"app\" {\n  name       = \"app-db\"\n  engine     = \"pg\"\n  version    = \"15\"\n  size       = \"db-s-2vcpu-4gb\"\n  region     = \"nyc3\"\n  node_count = 2\n}\n"},
	"do-db-firewall-includes-public": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_database_firewall\" \"app\" {\n  cluster_id = digitalocean_database_cluster.app.id\n  rule { type = \"droplet\"; value = digitalocean_droplet.web.id }\n  # Remove any rule with type=\"ip_addr\" value=\"0.0.0.0/0\".\n}\n"},
	"do-db-ip-only-trust": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_database_firewall\" \"app\" {\n  cluster_id = digitalocean_database_cluster.app.id\n  rule { type = \"droplet\"; value = digitalocean_droplet.web.id }\n  rule { type = \"tag\";     value = \"app-tier\" }\n}\n"},
	"do-db-no-firewall-rules": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_database_firewall\" \"app\" {\n  cluster_id = digitalocean_database_cluster.app.id\n  rule { type = \"droplet\"; value = digitalocean_droplet.web.id }\n}\n"},
	"do-db-single-node": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_database_cluster\" \"app\" {\n  name       = \"app-db\"\n  engine     = \"pg\"\n  size       = \"db-s-2vcpu-4gb\"\n  region     = \"nyc3\"\n  node_count = 3\n}\n"},
}

func init() { registerLegacyTF(legacyDatabasesTFEntries) }
