package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func init() {
	register("bash-do-droplet-stopped-too-long",
		[]string{"do-droplet-stopped-too-long"}, renderBashDropletStopped)
	register("bash-do-project-no-purpose",
		[]string{"do-project-no-purpose"}, renderBashProjectPurpose)
	register("bash-do-droplet-aged-rightsizing",
		[]string{"do-droplet-aged-no-rightsizing"}, renderBashDropletRightsize)
	register("bash-do-billing-monthly-alert-review",
		[]string{"do-billing-monthly-alert-review"}, renderBashBillingDashboard)
	register("bash-do-billing-payment-method-valid",
		[]string{"do-billing-payment-method-valid"}, renderBashBillingDashboard)
	register("bash-do-billing-cost-breakout-documented",
		[]string{"do-billing-cost-breakout-documented"}, renderBashInvoicePull)
	register("bash-do-billing-reserved-commitments",
		[]string{"do-billing-reserved-commitments-reviewed"}, renderBashBillingDashboard)
	register("bash-do-billing-database-pause-audit",
		[]string{"do-billing-database-pause-audit"}, renderBashDBPauseAudit)
	register("bash-do-billing-snapshot-retention",
		[]string{"do-billing-snapshot-retention-policy"}, renderBashSnapshotRetention)
	register("bash-do-billing-cdn-traffic-cost",
		[]string{"do-billing-cdn-traffic-cost"}, renderBashBillingDashboard)
}

func renderBashDropletStopped(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "DROPLET"
	}
	body := fmt.Sprintf(`name=%q
doctl compute droplet-action snapshot "$name" --snapshot-name "${name}-backup-$(date +%%Y%%m%%d)"
doctl compute droplet delete "$name" --force`, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderBashProjectPurpose(f core.Finding) (remediate.Snippet, error) {
	id := f.Resource.Name
	if id == "" {
		id = "PROJECT_ID"
	}
	body := fmt.Sprintf(`doctl projects update %s --purpose "Web Application" --environment Production --description "Production web app"`, id)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderBashDropletRightsize(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "DROPLET"
	}
	body := fmt.Sprintf(`doctl monitoring metrics droplet --droplet-id %s --duration 30d --metric cpu_user
# Review then resize:
# doctl compute droplet-action resize %s --size s-1vcpu-2gb`, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderBashBillingDashboard(_ core.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"billing dashboard control",
		"https://cloud.digitalocean.com/account/billing",
		"Quarterly review; capture screenshots for audit evidence")
}

func renderBashInvoicePull(_ core.Finding) (remediate.Snippet, error) {
	body := `inv="$(doctl invoice list --no-header --format InvoiceUUID | head -1)"
doctl invoice get-csv "$inv" > "invoice-$(date +%Y-%m).csv"`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
	}, nil
}

func renderBashDBPauseAudit(_ core.Finding) (remediate.Snippet, error) {
	body := `doctl databases list --format ID,Name,Engine,Status -o json \
  | jq -r '.[] | select(.status=="offline") | "\(.id)\t\(.name)\t\(.engine)"'`
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderBashSnapshotRetention(_ core.Finding) (remediate.Snippet, error) {
	body := `# Retire snapshots older than 90 days.
threshold="$(date -u -d '90 days ago' +%s 2>/dev/null || date -u -v-90d +%s)"
doctl compute snapshot list -o json \
  | jq -r --arg t "$threshold" '.[] | select((.created_at | fromdateiso8601) < ($t|tonumber)) | .id' \
  | xargs -r -n1 doctl compute snapshot delete --force`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

// v0.19 phase 9 — legacy backfill for billing-adjacent checks.
var legacyBillingBashEntries = map[string]legacyBashEntry{
	"do-monitoring-disabled-alert":      {risk: remediate.RiskSafe, body: "doctl monitoring alert update ALERT_ID --enabled"},
	"do-monitoring-no-alerts":           {risk: remediate.RiskSafe, body: "doctl monitoring alert create --type v1/insights/droplet/cpu --description \"CPU > 80%\" --compare GreaterThan --value 80 --window 5m --emails ops@example.com"},
	"do-project-default-no-description": {risk: remediate.RiskSafe, body: "doctl projects update PROJECT_ID --description \"Production web app\""},
	"do-project-no-environment":         {risk: remediate.RiskSafe, body: "doctl projects update PROJECT_ID --environment Production"},
	"do-registry-empty":                 {risk: remediate.RiskReview, body: "doctl registry delete REGISTRY_NAME --force"},
	"do-registry-no-recent-gc":          {risk: remediate.RiskSafe, body: "doctl registry garbage-collection start --include-untagged-manifests REGISTRY_NAME"},
	"do-registry-starter-tier":          {risk: remediate.RiskReview, body: "doctl registry subscription update --tier-slug basic"},
	"do-snapshot-orphan-source":         {risk: remediate.RiskReview, body: "doctl compute snapshot delete SNAPSHOT_ID --force"},
	"do-snapshot-too-old":               {risk: remediate.RiskReview, body: "doctl compute snapshot delete SNAPSHOT_ID --force"},
	"do-image-public":                   {risk: remediate.RiskReview, body: "doctl compute image update IMAGE_ID --public=false"},
	"do-image-too-old":                  {risk: remediate.RiskReview, body: "doctl compute image delete IMAGE_ID"},
}

func init() { registerLegacyBash(legacyBillingBashEntries) }
