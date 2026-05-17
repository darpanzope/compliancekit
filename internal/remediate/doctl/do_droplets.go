package doctl

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage droplet checks.
var legacyDropletsDoctlEntries = map[string]legacyDoctlEntry{
	"do-droplet-backups-disabled":            {risk: remediate.RiskSafe, content: "doctl compute droplet-action enable-backups DROPLET_ID", verify: "doctl compute droplet get DROPLET_ID --format Features"},
	"do-droplet-monitoring-disabled":         {risk: remediate.RiskSafe, content: "doctl compute droplet-action enable-monitoring DROPLET_ID"},
	"do-droplet-no-firewall":                 {risk: remediate.RiskReview, content: "doctl compute firewall add-droplets FW_ID --droplet-ids DROPLET_ID"},
	"do-droplet-no-tags":                     {risk: remediate.RiskSafe, content: "doctl compute droplet tag --tag-name env:production DROPLET_ID"},
	"do-droplet-old-image":                   {risk: remediate.RiskReview, content: "doctl compute droplet-action rebuild DROPLET_ID --image-id NEW_IMAGE_ID"},
	"do-droplet-private-networking-disabled": {risk: remediate.RiskReview, content: "# Private networking is set at create; recreate in a VPC.\ndoctl compute droplet create new --size s-1vcpu-2gb --region nyc3 --image ubuntu-22-04-x64 --vpc-uuid VPC_UUID"},
	"do-droplet-status-non-active":           {risk: remediate.RiskReview, content: "doctl compute droplet-action power-on DROPLET_ID"},
}

func init() { registerLegacyDoctl(legacyDropletsDoctlEntries) }
