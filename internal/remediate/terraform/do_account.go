package terraform

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/core"
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
)

// v0.19 phase 1 — Terraform strategies for the 10 account-governance
// checks introduced in internal/checks/digitalocean/account_extra.go.
//
// Most account-scope DO controls aren't expressible in HCL — DO's
// dashboard-only MFA toggle, billing-alert form, audit-log retention
// selector etc. are not surfaced by the Terraform provider. For those
// checks the TF "remediation" is a documented stub: a commented HCL
// block pointing the operator at the dashboard URL plus the relevant
// `digitalocean_*` resource (if any) that *would* express the control.
//
// The monitoring-alert-coverage check is the exception — DO ships
// digitalocean_monitor_alert as a real TF resource, so the strategy
// emits four ready-to-paste blocks covering CPU + memory + disk + load.

func init() {
	register("tf-do-account-status-message-clean",
		[]string{"do-account-status-message-clean"}, renderTFAccountStatusMessage)
	register("tf-do-account-droplet-quota-headroom",
		[]string{"do-account-droplet-quota-headroom"}, renderTFAccountDropletQuota)
	register("tf-do-account-volume-quota-headroom",
		[]string{"do-account-volume-quota-headroom"}, renderTFAccountVolumeQuota)
	register("tf-do-account-reserved-ip-quota-headroom",
		[]string{"do-account-reserved-ip-quota-headroom"}, renderTFAccountReservedIPQuota)
	register("tf-do-account-monitoring-alert-coverage",
		[]string{"do-account-monitoring-alert-coverage"}, renderTFAccountAlertCoverage)
	register("tf-do-account-mfa-required",
		[]string{"do-account-mfa-required"}, renderTFAccountMFA)
	register("tf-do-account-api-token-rotation",
		[]string{"do-account-api-token-rotation-cadence"}, renderTFAccountTokenRotation)
	register("tf-do-account-audit-log-retention",
		[]string{"do-account-audit-log-retention"}, renderTFAccountAuditLog)
	register("tf-do-account-billing-alert-thresholds",
		[]string{"do-account-billing-alert-thresholds"}, renderTFAccountBillingAlerts)
	register("tf-do-account-owner-delegation",
		[]string{"do-account-owner-delegation-policy"}, renderTFAccountOwnerDelegation)
}

func renderTFAccountStatusMessage(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: `# Account status_message is a billing / ToS flag DigitalOcean sets
# server-side. No Terraform resource exposes or clears it — the
# remediation is to resolve the underlying issue (failed payment,
# ToS dispute) via the cloud panel banner. Once the issue is
# resolved the status_message clears server-side.
#
# Reference: https://cloud.digitalocean.com/account/billing
`,
		Notes: "Status_message can only be cleared by resolving the issue DO has flagged. Read the banner shown in the cloud panel.",
		Refs:  []string{"https://docs.digitalocean.com/support/billing/"},
	}, nil
}

func renderTFAccountDropletQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: "# DigitalOcean droplet_limit is set by DO support and isn't\n" +
			"# exposed by the Terraform provider. Two TF-friendly mitigations:\n" +
			"#\n" +
			"# 1. Prune orphan droplets — declare every droplet you USE in TF\n" +
			"#    and let `terraform destroy -target=digitalocean_droplet.legacy`\n" +
			"#    reclaim quota explicitly. Untracked droplets accumulate.\n" +
			"#\n" +
			"# 2. Pin a digitalocean_droplet count guardrail in CI so a runaway\n" +
			"#    autoscaler can't blow through quota:\n" +
			"#\n" +
			"#    locals {\n" +
			"#      max_droplets_per_env = 24\n" +
			"#    }\n" +
			"#    # check in CI: count of digitalocean_droplet.* must be <= local.max_droplets_per_env\n",
		Notes: "Request a quota bump via support if 80% utilization is the steady state. Prune orphans first.",
		Refs:  []string{"https://docs.digitalocean.com/products/account/limits/"},
	}, nil
}

func renderTFAccountVolumeQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: `# Same shape as droplet quota: volume_limit is DO-set and
# Terraform-opaque. Either request a bump via support, or prune
# orphan digitalocean_volume resources whose droplet_ids are []
# (the volume costs full price while attached to nothing).
#
# Useful CI guardrail:
#   count of digitalocean_volume.* must equal len(distinct droplet_ids set)
`,
		Notes: "Orphan volumes are the most common waste pattern. Audit before requesting a quota bump.",
		Refs:  []string{"https://docs.digitalocean.com/products/volumes/"},
	}, nil
}

func renderTFAccountReservedIPQuota(_ core.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: `# reserved_ip_limit is DO-set. Free orphans via Terraform:
#
#   resource "digitalocean_reserved_ip" "failover" {
#     droplet_id = digitalocean_droplet.web.id
#     region     = "nyc3"
#   }
#
# Any digitalocean_reserved_ip without droplet_id is paying for an
# unassigned IP. Either bind it via TF or remove the resource.
`,
		Notes: "Reserved IPs without an attached droplet are pure cost. Bind or remove.",
		Refs:  []string{"https://docs.digitalocean.com/products/networking/reserved-ips/"},
	}, nil
}

func renderTFAccountAlertCoverage(_ core.Finding) (remediate.Snippet, error) {
	b := render.NewHCLBlock("resource", "digitalocean_monitor_alert", "cpu_high")
	b.Attr("type", "v1/insights/droplet/cpu")
	b.Attr("compare", "GreaterThan")
	b.Attr("value", "80")
	b.Attr("window", "5m")
	b.Attr("description", "CPU > 80% for 5 min — added by v0.19 coverage backfill")
	b.RawAttr("tags", `["production"]`)
	b.RawAttr("entities", `[]`)
	b.RawAttr("alerts", `{
    email = ["ops@example.com"]
    slack = []
  }`)
	cpu := b.String()

	mem := `resource "digitalocean_monitor_alert" "memory_high" {
  type        = "v1/insights/droplet/memory_utilization_percent"
  compare     = "GreaterThan"
  value       = 85
  window      = "5m"
  description = "Memory > 85% for 5 min"
  tags        = ["production"]
  entities    = []
  alerts {
    email = ["ops@example.com"]
    slack = []
  }
}
`
	disk := `resource "digitalocean_monitor_alert" "disk_high" {
  type        = "v1/insights/droplet/disk_utilization_percent"
  compare     = "GreaterThan"
  value       = 80
  window      = "5m"
  description = "Disk > 80% for 5 min"
  tags        = ["production"]
  entities    = []
  alerts {
    email = ["ops@example.com"]
    slack = []
  }
}
`
	load := `resource "digitalocean_monitor_alert" "load_high" {
  type        = "v1/insights/droplet/load_5"
  compare     = "GreaterThan"
  value       = 4
  window      = "5m"
  description = "5-min load > 4 sustained"
  tags        = ["production"]
  entities    = []
  alerts {
    email = ["ops@example.com"]
    slack = []
  }
}
`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true,
		Content:   cpu + "\n" + mem + "\n" + disk + "\n" + load,
		VerifyCmd: "doctl monitoring alert list --format Type,Description,Enabled",
		Notes:     "Four basic ops alerts. Swap the email + slack channels for your real escalation paths. Tags can target a subset of droplets if you don't want fleet-wide coverage.",
		Refs: []string{
			"https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/monitor_alert",
		},
	}, nil
}

func renderTFAccountMFA(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"MFA enforcement is a dashboard-only setting; no Terraform resource toggles it",
		"https://cloud.digitalocean.com/account/security",
		"Settings → Security → 'Require two-factor authentication'")
}

func renderTFAccountTokenRotation(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"API token lifecycle (create / revoke / introspect) is not exposed by the Terraform provider",
		"https://cloud.digitalocean.com/account/api/tokens",
		"API → Tokens → revoke + reissue, then rotate consumers")
}

func renderTFAccountAuditLog(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Audit-log retention + export is a dashboard-only configuration",
		"https://cloud.digitalocean.com/account/audit-logs",
		"Settings → Audit Logs → enable export to Splunk/Datadog/S3 for ≥90d retention")
}

func renderTFAccountBillingAlerts(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Billing alerts are configured via the dashboard; no TF resource exists",
		"https://cloud.digitalocean.com/account/billing",
		"Settings → Billing → Alerts → set 80% + 100% monthly thresholds")
}

func renderTFAccountOwnerDelegation(_ core.Finding) (remediate.Snippet, error) {
	return renderTFManualOnly(
		"Team owner / member roles are dashboard-only; the Terraform provider does not expose digitalocean_team_member",
		"https://cloud.digitalocean.com/account/team",
		"Settings → Team → ensure ≥2 Owners (or document a delegate)")
}

func renderTFManualOnly(reason, dashboardURL, action string) (remediate.Snippet, error) {
	body := fmt.Sprintf("# %s.\n#\n"+
		"# Manual remediation:\n#   %s\n#\n"+
		"# Dashboard:\n#   %s\n#\n"+
		"# After remediation, capture a screenshot of the configured state for\n"+
		"# the audit evidence pack and re-run `compliancekit scan` so the finding\n"+
		"# clears (it will remain as a manual-verify error until the auditor\n"+
		"# overrides via a waivers.yaml entry per ADR-013).\n",
		reason, action, dashboardURL)
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: body,
		Notes: "Account-level control without a TF surface. Record evidence in waivers.yaml or attach a manual evidence artifact alongside the report.",
		Refs:  []string{dashboardURL},
	}, nil
}
