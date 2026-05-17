package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 8 — Terraform strategies for billing + project hygiene.

func init() {
	register("tf-do-droplet-stopped-too-long",
		[]string{"do-droplet-stopped-too-long"}, renderTFDropletStopped)
	register("tf-do-project-no-purpose",
		[]string{"do-project-no-purpose"}, renderTFProjectPurpose)
	register("tf-do-droplet-aged-rightsizing",
		[]string{"do-droplet-aged-no-rightsizing"}, renderTFDropletRightsize)
	register("tf-do-billing-monthly-alert-review",
		[]string{"do-billing-monthly-alert-review"}, renderTFBillingManual)
	register("tf-do-billing-payment-method-valid",
		[]string{"do-billing-payment-method-valid"}, renderTFBillingManual)
	register("tf-do-billing-cost-breakout-documented",
		[]string{"do-billing-cost-breakout-documented"}, renderTFBillingManual)
	register("tf-do-billing-reserved-commitments",
		[]string{"do-billing-reserved-commitments-reviewed"}, renderTFBillingManual)
	register("tf-do-billing-database-pause-audit",
		[]string{"do-billing-database-pause-audit"}, renderTFBillingManual)
	register("tf-do-billing-snapshot-retention",
		[]string{"do-billing-snapshot-retention-policy"}, renderTFSnapshotRetention)
	register("tf-do-billing-cdn-traffic-cost",
		[]string{"do-billing-cdn-traffic-cost"}, renderTFCDNCost)
}

func renderTFDropletStopped(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "DROPLET")
	body := fmt.Sprintf(`# Either remove the resource (preferred) or document why it stays.
# Drop the block from your .tf source AND run:
#   terraform state rm digitalocean_droplet.%s
# Then via doctl:
#   doctl compute droplet-action snapshot %s --snapshot-name backup
#   doctl compute droplet delete %s --force
`, tfIdent(name), name, name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Snapshot first if state is non-trivial. Confirm with owner before destroy.",
	}, nil
}

func renderTFProjectPurpose(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "PROJECT")
	body := fmt.Sprintf(`resource "digitalocean_project" %q {
  name        = %q
  description = "Production web application — owns droplets + databases."
  purpose     = "Web Application"
  environment = "Production"
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
	}, nil
}

func renderTFDropletRightsize(f core.Finding) (remediate.Snippet, error) {
	name := tfNameOrFallback(f, "DROPLET")
	body := fmt.Sprintf(`# Resize after reviewing monitoring data.
resource "digitalocean_droplet" %q {
  name  = %q
  size  = "s-2vcpu-4gb"  # adjust based on sustained CPU + memory
  image = "ubuntu-22-04-x64"
  # ... existing fields ...
}
`, tfIdent(name), name)
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: body,
		Notes: "Resize triggers reboot for size-class changes. Plan a maintenance window.",
	}, nil
}

func renderTFBillingManual(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"billing controls are dashboard-only (no TF surface)",
		"https://cloud.digitalocean.com/account/billing",
		"Quarterly review on the billing dashboard; capture screenshots for the audit pack")
}

func renderTFSnapshotRetention(_ core.Finding) (remediate.Snippet, error) {
	body := `# Snapshot retention is enforced by a scheduled GitHub Action or cron;
# Terraform doesn't natively model 'delete snapshots older than X days'.
# Example workflow shape:

# .github/workflows/snapshot-retention.yml:
#   schedule: cron: '0 4 * * 0'
#   jobs:
#     retention:
#       steps:
#         - run: doctl compute snapshot list -o json
#               | jq -r '.[] | select((now - (.created_at|fromdate)) > (90*24*3600)) | .id'
#               | xargs -r -n1 doctl compute snapshot delete --force
`
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false, Content: body,
		Notes: "Wire up via GitHub Actions / GitLab pipelines / a droplet cron. Pick retention to match RPO + audit SLA.",
	}, nil
}

func renderTFCDNCost(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"CDN traffic cost",
		"https://cloud.digitalocean.com/spaces",
		"Review CDN bandwidth in the billing breakout; audit Cache-Control + TTL if unexpected")
}
