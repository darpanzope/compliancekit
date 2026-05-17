package doctl

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
)

// v0.19 phase 1 — doctl strategies for the 10 account-governance
// checks. For the two categories of finding:
//
//	REAL-DATA   — emit an actionable `doctl monitoring alert create`
//	              one-liner (alert-coverage) or an inspection one-liner
//	              that lists offenders (quota headroom checks).
//	MANUAL-VERIFY — emit `doctl auth init` reminder + the dashboard URL
//	              the auditor opens.

func init() {
	register("doctl-do-account-status-message-clean",
		[]string{"do-account-status-message-clean"}, renderDoctlAccountStatusMessage)
	register("doctl-do-account-droplet-quota-headroom",
		[]string{"do-account-droplet-quota-headroom"}, renderDoctlAccountDropletQuota)
	register("doctl-do-account-volume-quota-headroom",
		[]string{"do-account-volume-quota-headroom"}, renderDoctlAccountVolumeQuota)
	register("doctl-do-account-reserved-ip-quota-headroom",
		[]string{"do-account-reserved-ip-quota-headroom"}, renderDoctlAccountReservedIPQuota)
	register("doctl-do-account-monitoring-alert-coverage",
		[]string{"do-account-monitoring-alert-coverage"}, renderDoctlAccountAlertCoverage)
	register("doctl-do-account-mfa-required",
		[]string{"do-account-mfa-required"}, renderDoctlAccountMFA)
	register("doctl-do-account-api-token-rotation",
		[]string{"do-account-api-token-rotation-cadence"}, renderDoctlAccountTokenRotation)
	register("doctl-do-account-audit-log-retention",
		[]string{"do-account-audit-log-retention"}, renderDoctlAccountAuditLog)
	register("doctl-do-account-billing-alert-thresholds",
		[]string{"do-account-billing-alert-thresholds"}, renderDoctlAccountBillingAlerts)
	register("doctl-do-account-owner-delegation",
		[]string{"do-account-owner-delegation-policy"}, renderDoctlAccountOwnerDelegation)
}

func renderDoctlAccountStatusMessage(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: "# Inspect the account flag set by DigitalOcean:\n" +
			"doctl account get --format Status,StatusMessage,Email\n\n" +
			"# Resolve the underlying issue (billing, ToS) via the cloud panel:\n" +
			"#   https://cloud.digitalocean.com/account/billing\n" +
			"# Once resolved, the status_message clears server-side.",
		VerifyCmd: "doctl account get --format Status,StatusMessage",
		Notes:     "doctl reads server-side state; cannot mutate the flag. Address the root cause in the cloud panel.",
	}, nil
}

func renderDoctlAccountDropletQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: "# 1. Show current limit + usage:\n" +
			"doctl account get --format DropletLimit\n" +
			"doctl compute droplet list --format ID,Name,Status,Created | wc -l\n\n" +
			"# 2. Find stale droplets (>180 days, status=off):\n" +
			"doctl compute droplet list --format ID,Name,Created,Status -o json \\\n" +
			"  | jq -r '.[] | select(.status == \"off\") | [.id, .name, .created_at] | @tsv'\n\n" +
			"# 3. Destroy stale: doctl compute droplet delete <ID> --force",
		VerifyCmd: "doctl compute droplet list --format ID,Name,Status,Created",
		Notes:     "Run inspection first. Confirm each droplet with the workload owner before destroying.",
	}, nil
}

func renderDoctlAccountVolumeQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: "# 1. Show current limit + usage:\n" +
			"doctl account get --format VolumeLimit\n" +
			"doctl compute volume list --format ID,Name,DropletIDs,SizeGigaBytes | wc -l\n\n" +
			"# 2. Find orphan volumes (no DropletIDs):\n" +
			"doctl compute volume list -o json \\\n" +
			"  | jq -r '.[] | select((.droplet_ids | length) == 0) | [.id, .name, .size_gigabytes] | @tsv'\n\n" +
			"# 3. Delete orphan: doctl compute volume delete <ID> --force",
		VerifyCmd: "doctl compute volume list --format Name,DropletIDs,SizeGigaBytes",
		Notes:     "Orphan volumes are the most common quota-waste pattern. Verify before delete.",
	}, nil
}

func renderDoctlAccountReservedIPQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: false,
		Content: "# 1. Show current limit + usage:\n" +
			"doctl account get --format ReservedIPLimit\n" +
			"doctl compute reserved-ip list --format IP,DropletID,Region | wc -l\n\n" +
			"# 2. Find unassigned reserved IPs:\n" +
			"doctl compute reserved-ip list -o json \\\n" +
			"  | jq -r '.[] | select(.droplet == null) | [.ip, .region.slug] | @tsv'\n\n" +
			"# 3. Release: doctl compute reserved-ip delete <IP> --force",
		VerifyCmd: "doctl compute reserved-ip list --format IP,DropletID",
		Notes:     "Unassigned reserved IPs are billed at full rate. Release any not pinned for failover.",
	}, nil
}

func renderDoctlAccountAlertCoverage(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: `# Add the four basics. Replace ops@example.com with your real list.

doctl monitoring alert create \
  --type   v1/insights/droplet/cpu \
  --description "CPU > 80% for 5 min" \
  --compare GreaterThan --value 80 --window 5m \
  --emails ops@example.com \
  --tags production

doctl monitoring alert create \
  --type   v1/insights/droplet/memory_utilization_percent \
  --description "Memory > 85% for 5 min" \
  --compare GreaterThan --value 85 --window 5m \
  --emails ops@example.com \
  --tags production

doctl monitoring alert create \
  --type   v1/insights/droplet/disk_utilization_percent \
  --description "Disk > 80% for 5 min" \
  --compare GreaterThan --value 80 --window 5m \
  --emails ops@example.com \
  --tags production

doctl monitoring alert create \
  --type   v1/insights/droplet/load_5 \
  --description "5-min load > 4" \
  --compare GreaterThan --value 4 --window 5m \
  --emails ops@example.com \
  --tags production`,
		VerifyCmd: "doctl monitoring alert list --format Type,Description,Enabled",
		Notes:     "Idempotent at the alert-type level: re-running creates duplicates. Audit existing alerts first if you've already partially rolled this out.",
	}, nil
}

func renderDoctlAccountMFA(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"MFA enforcement",
		"https://cloud.digitalocean.com/account/security",
		"Settings → Security → 'Require two-factor authentication'")
}

func renderDoctlAccountTokenRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"API token rotation",
		"https://cloud.digitalocean.com/account/api/tokens",
		"API → Tokens → revoke > 90-day-old tokens, reissue, rotate consumers")
}

func renderDoctlAccountAuditLog(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"audit-log retention",
		"https://cloud.digitalocean.com/account/audit-logs",
		"Settings → Audit Logs → enable export to extend retention to ≥90d")
}

func renderDoctlAccountBillingAlerts(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"billing alert thresholds",
		"https://cloud.digitalocean.com/account/billing",
		"Settings → Billing → Alerts → set 80% + 100% monthly thresholds")
}

func renderDoctlAccountOwnerDelegation(_ core.Finding) (remediate.Snippet, error) {
	return renderDoctlManualOnly(
		"owner-delegation policy",
		"https://cloud.digitalocean.com/account/team",
		"Settings → Team → ensure ≥2 Owners, document the delegation procedure")
}

func renderDoctlManualOnly(label, dashboardURL, action string) (remediate.Snippet, error) {
	body := fmt.Sprintf(
		"# %s — doctl has no subcommand for this control surface.\n"+
			"# Verify authentication: doctl auth list\n"+
			"# Then open the dashboard:\n"+
			"#   %s\n"+
			"# Action: %s",
		label, dashboardURL, action)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Dashboard-only control. Capture a screenshot for the audit evidence pack.",
		Refs:  []string{dashboardURL},
	}, nil
}
