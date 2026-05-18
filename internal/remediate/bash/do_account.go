package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 1 — bash strategies for the 10 account-governance checks.
//
// For each: a POSIX-sh one-liner using doctl + jq for the live-data
// checks, and an xdg-open / open invocation with text fallback for the
// dashboard-only manual-verify checks.

func init() {
	register("bash-do-account-status-message-clean",
		[]string{"do-account-status-message-clean"}, renderBashAccountStatusMessage)
	register("bash-do-account-droplet-quota-headroom",
		[]string{"do-account-droplet-quota-headroom"}, renderBashAccountDropletQuota)
	register("bash-do-account-volume-quota-headroom",
		[]string{"do-account-volume-quota-headroom"}, renderBashAccountVolumeQuota)
	register("bash-do-account-reserved-ip-quota-headroom",
		[]string{"do-account-reserved-ip-quota-headroom"}, renderBashAccountReservedIPQuota)
	register("bash-do-account-monitoring-alert-coverage",
		[]string{"do-account-monitoring-alert-coverage"}, renderBashAccountAlertCoverage)
	register("bash-do-account-mfa-required",
		[]string{"do-account-mfa-required"}, renderBashAccountMFA)
	register("bash-do-account-api-token-rotation",
		[]string{"do-account-api-token-rotation-cadence"}, renderBashAccountTokenRotation)
	register("bash-do-account-audit-log-retention",
		[]string{"do-account-audit-log-retention"}, renderBashAccountAuditLog)
	register("bash-do-account-billing-alert-thresholds",
		[]string{"do-account-billing-alert-thresholds"}, renderBashAccountBillingAlerts)
	register("bash-do-account-owner-delegation",
		[]string{"do-account-owner-delegation-policy"}, renderBashAccountOwnerDelegation)
}

func renderBashAccountStatusMessage(_ compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Pull current status_message and exit non-zero if non-empty.
msg="$(curl -fsSL -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
  https://api.digitalocean.com/v2/account | jq -r '.account.status_message // ""')"
if [ -n "$msg" ]; then
  printf 'account flagged: %s\n' "$msg" >&2
  printf 'resolve via https://cloud.digitalocean.com/account/billing\n' >&2
  exit 1
fi
printf 'account status_message clear\n'`,
		VerifyCmd: `curl -fsSL -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" https://api.digitalocean.com/v2/account | jq -r .account.status_message`,
		Notes:     "Requires DIGITALOCEAN_TOKEN in env. Read-only; cannot clear the flag.",
	}, nil
}

func renderBashAccountDropletQuota(_ compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Report droplet utilization vs limit, fail at >80%.
limit="$(doctl account get --no-header --format DropletLimit)"
used="$(doctl compute droplet list --no-header --format ID | wc -l | tr -d ' ')"
pct=$(( used * 100 / limit ))
printf 'droplets: %d / %d (%d%%)\n' "$used" "$limit" "$pct"
if [ "$pct" -gt 80 ]; then
  printf 'over 80%% utilization — prune or request quota bump\n' >&2
  doctl compute droplet list --format ID,Name,Status,Created \
    | sort -k3 | head -20
  exit 1
fi`,
		VerifyCmd:   "doctl account get --format DropletLimit && doctl compute droplet list --format ID | wc -l",
		RollbackCmd: "# No rollback — this is read-only reporting.",
		Notes:       "Run weekly in CI to catch quota drift before it bites.",
	}, nil
}

func renderBashAccountVolumeQuota(_ compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Report volume utilization vs limit.
limit="$(doctl account get --no-header --format VolumeLimit)"
used="$(doctl compute volume list --no-header --format ID | wc -l | tr -d ' ')"
pct=$(( used * 100 / limit ))
printf 'volumes: %d / %d (%d%%)\n' "$used" "$limit" "$pct"
# Spotlight orphans (no attached droplet):
doctl compute volume list -o json \
  | jq -r '.[] | select((.droplet_ids | length) == 0) | "\(.id)\t\(.name)\t\(.size_gigabytes)GB"'
if [ "$pct" -gt 80 ]; then exit 1; fi`,
		VerifyCmd: "doctl compute volume list --format Name,DropletIDs,SizeGigaBytes",
		Notes:     "Orphan volumes shown for manual review even when under quota.",
	}, nil
}

func renderBashAccountReservedIPQuota(_ compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true,
		Content: `# Report reserved-IP utilization + orphans.
limit="$(doctl account get --no-header --format ReservedIPLimit)"
used="$(doctl compute reserved-ip list --no-header --format IP | wc -l | tr -d ' ')"
pct=$(( used * 100 / limit ))
printf 'reserved IPs: %d / %d (%d%%)\n' "$used" "$limit" "$pct"
doctl compute reserved-ip list -o json \
  | jq -r '.[] | select(.droplet == null) | "\(.ip)\t\(.region.slug)"'
if [ "$pct" -gt 80 ]; then exit 1; fi`,
		VerifyCmd: "doctl compute reserved-ip list --format IP,DropletID",
		Notes:     "Unassigned reserved IPs cost full price. Release any not held for failover.",
	}, nil
}

func renderBashAccountAlertCoverage(_ compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content: `# Idempotent-ish: skip create when an enabled alert of the type already exists.
have() {
  doctl monitoring alert list -o json \
    | jq -e --arg t "$1" '.[] | select(.enabled and (.type | startswith($t)))' >/dev/null
}
ops_email="${OPS_EMAIL:-ops@example.com}"

have v1/insights/droplet/cpu                          || doctl monitoring alert create --type v1/insights/droplet/cpu                          --description "CPU > 80% for 5 min"    --compare GreaterThan --value 80 --window 5m --emails "$ops_email"
have v1/insights/droplet/memory_utilization_percent   || doctl monitoring alert create --type v1/insights/droplet/memory_utilization_percent   --description "Memory > 85% for 5 min" --compare GreaterThan --value 85 --window 5m --emails "$ops_email"
have v1/insights/droplet/disk_utilization_percent     || doctl monitoring alert create --type v1/insights/droplet/disk_utilization_percent     --description "Disk > 80% for 5 min"   --compare GreaterThan --value 80 --window 5m --emails "$ops_email"
have v1/insights/droplet/load_5                       || doctl monitoring alert create --type v1/insights/droplet/load_5                       --description "5-min load > 4"         --compare GreaterThan --value 4  --window 5m --emails "$ops_email"`,
		VerifyCmd: "doctl monitoring alert list --format Type,Description,Enabled",
		Notes:     "Set OPS_EMAIL env var or edit ops_email in the script. The have() guard makes re-runs safe.",
	}, nil
}

func renderBashAccountMFA(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"MFA enforcement",
		"https://cloud.digitalocean.com/account/security",
		"Toggle on 'Require two-factor authentication'")
}

func renderBashAccountTokenRotation(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"API token rotation",
		"https://cloud.digitalocean.com/account/api/tokens",
		"Sort by Last Used; revoke tokens >90d or stale >30d; reissue + rotate")
}

func renderBashAccountAuditLog(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"audit-log retention",
		"https://cloud.digitalocean.com/account/audit-logs",
		"Enable export to Splunk / Datadog / S3 for ≥90d retention")
}

func renderBashAccountBillingAlerts(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"billing alert thresholds",
		"https://cloud.digitalocean.com/account/billing",
		"Set monthly 80% + 100% thresholds, route to finance + eng distros")
}

func renderBashAccountOwnerDelegation(_ compliancekit.Finding) (remediate.Snippet, error) {
	return renderBashManualOnly(
		"owner-delegation policy",
		"https://cloud.digitalocean.com/account/team",
		"Confirm ≥2 Owners or document the delegate procedure")
}

func renderBashManualOnly(label, dashboardURL, action string) (remediate.Snippet, error) {
	body := fmt.Sprintf(`# %s — dashboard-only control, no API surface.
# Open the dashboard page (works on macOS via 'open', Linux via xdg-open):
url=%q
if command -v open >/dev/null 2>&1; then
  open "$url"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$url"
else
  printf 'open this URL in a browser:\n  %%s\n' "$url"
fi
# Action: %s
# Capture a screenshot for the audit evidence pack.`, label, dashboardURL, action)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Dashboard-only. Screenshot evidence required for the audit pack.",
		Refs:  []string{dashboardURL},
	}, nil
}

// v0.19 phase 9 — legacy backfill for v0.9-vintage account checks.
var legacyAccountBashEntries = map[string]legacyBashEntry{
	"do-account-email-verified":  {risk: remediate.RiskManual, body: "doctl account get --format Email,EmailVerified\n# Re-send verification from cloud panel."},
	"do-account-status-active":   {risk: remediate.RiskManual, body: "doctl account get --format Status,StatusMessage"},
	"do-account-uses-named-team": {risk: remediate.RiskManual, body: "echo 'create a team via cloud panel → Settings → Team' >&2"},
}

func init() { registerLegacyBash(legacyAccountBashEntries) }
