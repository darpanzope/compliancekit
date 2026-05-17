package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

func init() {
	register("doctl-do-droplet-stopped-too-long",
		[]string{"do-droplet-stopped-too-long"}, renderDoctlDropletStopped)
	register("doctl-do-project-no-purpose",
		[]string{"do-project-no-purpose"}, renderDoctlProjectPurpose)
	register("doctl-do-droplet-aged-rightsizing",
		[]string{"do-droplet-aged-no-rightsizing"}, renderDoctlDropletRightsize)
	register("doctl-do-billing-monthly-alert-review",
		[]string{"do-billing-monthly-alert-review"}, renderDoctlBillingDashboard)
	register("doctl-do-billing-payment-method-valid",
		[]string{"do-billing-payment-method-valid"}, renderDoctlBillingDashboard)
	register("doctl-do-billing-cost-breakout-documented",
		[]string{"do-billing-cost-breakout-documented"}, renderDoctlInvoicePull)
	register("doctl-do-billing-reserved-commitments",
		[]string{"do-billing-reserved-commitments-reviewed"}, renderDoctlBillingDashboard)
	register("doctl-do-billing-database-pause-audit",
		[]string{"do-billing-database-pause-audit"}, renderDoctlDBPauseAudit)
	register("doctl-do-billing-snapshot-retention",
		[]string{"do-billing-snapshot-retention-policy"}, renderDoctlSnapshotRetention)
	register("doctl-do-billing-cdn-traffic-cost",
		[]string{"do-billing-cdn-traffic-cost"}, renderDoctlBillingDashboard)
}

func renderDoctlDropletStopped(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "DROPLET"
	}
	body := fmt.Sprintf(`# Snapshot then delete the stale droplet.
doctl compute droplet-action snapshot %s --snapshot-name "%s-backup-$(date +%%Y%%m%%d)"
doctl compute droplet delete %s --force`, name, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlProjectPurpose(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "PROJECT_ID"
	}
	body := fmt.Sprintf(`doctl projects update %s \
  --purpose "Web Application" \
  --environment Production \
  --description "Production web app"`, name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderDoctlDropletRightsize(f core.Finding) (remediate.Snippet, error) {
	name := f.Resource.Name
	if name == "" {
		name = "DROPLET"
	}
	body := fmt.Sprintf(`# 1. Inspect sustained CPU + memory utilization.
doctl monitoring metrics droplet --droplet-id %s --duration 30d --metric cpu_user
# 2. Resize (requires reboot for size-class changes).
# doctl compute droplet-action resize %s --size s-1vcpu-2gb`, name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlBillingDashboard(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"billing dashboard control",
		"https://cloud.digitalocean.com/account/billing",
		"Quarterly review; capture screenshots for audit evidence")
}

func renderDoctlInvoicePull(_ core.Finding) (remediate.Snippet, error) {
	body := `# Monthly invoice + per-project breakout export.
doctl invoice list --format InvoiceUUID,Amount,InvoicePeriod
# Fetch the line items:
doctl invoice get-pdf <invoice-uuid> > invoice.pdf
doctl invoice get-csv <invoice-uuid> > invoice.csv
# Group by project tag in finance spreadsheet.`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlDBPauseAudit(_ core.Finding) (remediate.Snippet, error) {
	body := `# List paused databases (still billed at standard rate).
doctl databases list --format ID,Name,Engine,Status \
  | awk '$4 == "offline"'`
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
	}, nil
}

func renderDoctlSnapshotRetention(_ core.Finding) (remediate.Snippet, error) {
	body := `# Delete snapshots older than 90 days.
threshold="$(date -u -d '90 days ago' +%s 2>/dev/null || date -u -v-90d +%s)"
doctl compute snapshot list -o json \
  | jq -r --arg t "$threshold" '.[] | select((.created_at | fromdateiso8601) < ($t|tonumber)) | .id' \
  | xargs -r -n1 doctl compute snapshot delete --force`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Date arithmetic differs between GNU + BSD; the fallback handles both. Confirm before running in production.",
	}, nil
}
