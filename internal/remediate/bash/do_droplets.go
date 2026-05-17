package bash

import "github.com/darpanzope/compliancekit/internal/remediate"

// v0.19 phase 9 — legacy backfill for v0.9-vintage droplet checks.
var legacyDropletsBashEntries = map[string]legacyBashEntry{
	"do-droplet-backups-disabled":            {risk: remediate.RiskSafe, body: "doctl compute droplet-action enable-backups DROPLET_ID"},
	"do-droplet-monitoring-disabled":         {risk: remediate.RiskSafe, body: "doctl compute droplet-action enable-monitoring DROPLET_ID"},
	"do-droplet-no-firewall":                 {risk: remediate.RiskReview, body: "doctl compute firewall add-droplets FW_ID --droplet-ids DROPLET_ID"},
	"do-droplet-no-tags":                     {risk: remediate.RiskSafe, body: "doctl compute droplet tag --tag-name env:production DROPLET_ID"},
	"do-droplet-no-vpc":                      {risk: remediate.RiskReview, body: "echo 'Droplet VPC is set at create; recreate in VPC' >&2"},
	"do-droplet-old-image":                   {risk: remediate.RiskReview, body: "doctl compute droplet-action rebuild DROPLET_ID --image-id NEW_IMAGE_ID"},
	"do-droplet-private-networking-disabled": {risk: remediate.RiskReview, body: "echo 'private_networking is set at create; recreate droplet in a VPC' >&2"},
	"do-droplet-status-non-active":           {risk: remediate.RiskReview, body: "doctl compute droplet-action power-on DROPLET_ID"},
}

func init() { registerLegacyBash(legacyDropletsBashEntries) }
