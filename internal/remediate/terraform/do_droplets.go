package terraform

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage droplet checks.

var legacyDropletsTFEntries = map[string]legacyTFEntry{
	"do-droplet-backups-disabled": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_droplet\" \"web\" {\n  name    = \"web\"\n  backups = true\n}\n"},
	"do-droplet-monitoring-disabled": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_droplet\" \"web\" {\n  name       = \"web\"\n  monitoring = true\n}\n"},
	"do-droplet-no-firewall": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_firewall\" \"web\" {\n  name        = \"web-fw\"\n  droplet_ids = [digitalocean_droplet.web.id]\n  inbound_rule  { protocol = \"tcp\"; port_range = \"443\"; source_addresses = [\"0.0.0.0/0\"] }\n  outbound_rule { protocol = \"tcp\"; port_range = \"443\"; destination_addresses = [\"0.0.0.0/0\"] }\n}\n"},
	"do-droplet-no-tags": {risk: remediate.RiskSafe,
		content: "resource \"digitalocean_droplet\" \"web\" {\n  name = \"web\"\n  tags = [\"env:production\", \"team:platform\"]\n}\n"},
	"do-droplet-old-image": {risk: remediate.RiskReview,
		content: "# Rebuild on a newer image (in-place rebuild via doctl). TF can also recreate:\nresource \"digitalocean_droplet\" \"web\" {\n  name  = \"web\"\n  image = \"ubuntu-22-04-x64\"\n}\n"},
	"do-droplet-private-networking-disabled": {risk: remediate.RiskReview,
		content: "resource \"digitalocean_droplet\" \"web\" {\n  name     = \"web\"\n  vpc_uuid = digitalocean_vpc.prod.id\n}\n"},
	"do-droplet-status-non-active": {risk: remediate.RiskManual,
		content: "# Power-on is operational; no TF resource.\n# doctl compute droplet-action power-on DROPLET_ID"},
}

func init() { registerLegacyTF(legacyDropletsTFEntries) }
