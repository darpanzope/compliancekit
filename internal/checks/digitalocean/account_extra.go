package digitalocean

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.19 phase 1 — account/team governance deepening. Two flavors:
//
//	REAL-DATA   — exercise live godo.Account attributes (status_message,
//	              quota limits, alert-policy coverage).
//	MANUAL-VERIFY — DigitalOcean's public API does not expose MFA
//	              enforcement, API-token rotation cadence, audit-log
//	              retention, billing-alert thresholds, or owner-
//	              delegation policy. Auditors still need to record
//	              these controls; the checks emit StatusError with a
//	              dashboard URL so the gap is visible in the evidence
//	              pack instead of silently absent.
//
// All ten attach findings to the single AccountType anchor resource so
// they aggregate cleanly on the auditor's view.

// ----- shared helpers ---------------------------------------------------

const (
	accountQuotaWarnPct   = 80 // > 80% utilization → fail
	manualVerifyDashboard = "https://cloud.digitalocean.com"
)

func newAccountFinding(check compliancekit.Check, account compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: account.Ref(),
		Tags:     check.Tags,
	}
}

// manualVerify produces a StatusError finding pointing the auditor at
// the dashboard URL. Status is StatusError because we cannot make a
// pass/fail determination — but the auditor must record the control
// state to close the evidence loop, so the finding stays actionable
// (counts toward --fail-on gates).
func manualVerify(check compliancekit.Check, account compliancekit.Resource, control, url string) compliancekit.Finding {
	f := newAccountFinding(check, account)
	f.Status = compliancekit.StatusError
	f.Message = fmt.Sprintf("account %q: %s — DigitalOcean public API does not expose this control; verify at %s",
		account.Name, control, url)
	return f
}

// quotaHeadroom returns the fail/pass finding for a (used, limit, label)
// triple. limit ≤ 0 ⇒ unbounded (always pass); used > limit*0.80 ⇒ fail.
func quotaHeadroom(check compliancekit.Check, account compliancekit.Resource, used, limit int, label string) compliancekit.Finding {
	f := newAccountFinding(check, account)
	if limit <= 0 {
		f.Status = compliancekit.StatusSkip
		f.Message = fmt.Sprintf("account %q: %s has no published limit", account.Name, label)
		return f
	}
	if used*100 > limit*accountQuotaWarnPct {
		f.Status = compliancekit.StatusFail
		f.Message = fmt.Sprintf("account %q: %d/%d %s used (>%d%% threshold)",
			account.Name, used, limit, label, accountQuotaWarnPct)
		return f
	}
	f.Status = compliancekit.StatusPass
	f.Message = fmt.Sprintf("account %q: %d/%d %s used", account.Name, used, limit, label)
	return f
}

// ----- 1. status_message must be clean ----------------------------------

var CheckAccountStatusMessageClean = compliancekit.Check{
	ID:           "do-account-status-message-clean",
	Title:        "Account.status_message must be empty",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DO sets status_message when the account is flagged for " +
		"billing arrears, ToS review, or platform-team intervention. " +
		"Any non-empty value is a signal the account is restricted; " +
		"continuous-compliance evidence loses meaning while the flag " +
		"is in place.",
	Remediation: "Open the cloud panel banner DO shows when status_message " +
		"is non-empty; resolve the root cause (failed payment method, " +
		"ToS dispute, support ticket). Don't dismiss the banner without " +
		"reading it.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC2.1"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"11.1"},
	},
	Tags:    []string{"account", "platform-health"},
	Scanner: "account.StatusMessageClean",
}

func AccountStatusMessageClean(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		msg, _ := a.Attributes["status_message"].(string)
		f := newAccountFinding(CheckAccountStatusMessageClean, a)
		if strings.TrimSpace(msg) == "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: status_message empty", a.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: status_message=%q", a.Name, msg)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. droplet quota headroom ----------------------------------------

var CheckAccountDropletQuotaHeadroom = compliancekit.Check{
	ID:           "do-account-droplet-quota-headroom",
	Title:        "Droplet usage must leave >20% headroom against the account limit",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DO sets a per-account droplet_limit; bumping against it " +
		"means new droplets fail to provision — autoscalers stall, " +
		"recovery flows can't spin replacements, blue/green deploys " +
		"break. Production accounts should stay below 80% utilization " +
		"so a sudden burst (incident response, traffic spike) has " +
		"runway.",
	Remediation: "Two paths: (1) request a quota bump — 'doctl account ratelimit' " +
		"shows your support contact and the cloud panel has a quota " +
		"increase form. (2) Prune orphan droplets via 'doctl compute " +
		"droplet list --format ID,Name,Status,Created' and delete " +
		"anything stale.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"account", "capacity"},
	Scanner: "account.DropletQuotaHeadroom",
}

func AccountDropletQuotaHeadroom(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	used := len(g.ByType(docol.DropletType))
	for _, a := range g.ByType(docol.AccountType) {
		limit, _ := a.Attributes["droplet_limit"].(int)
		findings = append(findings, quotaHeadroom(CheckAccountDropletQuotaHeadroom, a, used, limit, "droplets"))
	}
	return findings, nil
}

// ----- 3. volume quota headroom -----------------------------------------

var CheckAccountVolumeQuotaHeadroom = compliancekit.Check{
	ID:           "do-account-volume-quota-headroom",
	Title:        "Block-storage volume usage must leave >20% headroom",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DO sets a per-account volume_limit. A volume exhaustion " +
		"event is a hard-stop for any droplet that needs persistent " +
		"storage attached on boot or after autoscaling. The same 80% " +
		"headroom rule applies; account-level limits are easier to " +
		"raise proactively than under incident pressure.",
	Remediation: "Request a quota bump from the cloud panel, OR prune " +
		"orphan volumes ('doctl compute volume list --format Name,DropletIDs,Size'). " +
		"Volumes with empty DropletIDs are paying for storage attached " +
		"to nothing.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"account", "capacity", "storage"},
	Scanner: "account.VolumeQuotaHeadroom",
}

func AccountVolumeQuotaHeadroom(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	used := len(g.ByType(docol.VolumeType))
	for _, a := range g.ByType(docol.AccountType) {
		limit, _ := a.Attributes["volume_limit"].(int)
		findings = append(findings, quotaHeadroom(CheckAccountVolumeQuotaHeadroom, a, used, limit, "volumes"))
	}
	return findings, nil
}

// ----- 4. reserved IP quota headroom ------------------------------------

var CheckAccountReservedIPQuotaHeadroom = compliancekit.Check{
	ID:           "do-account-reserved-ip-quota-headroom",
	Title:        "Reserved-IP usage must leave >20% headroom",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "Reserved IPs are the basis for static-IP services and " +
		"failover patterns. Hitting reserved_ip_limit during an " +
		"incident means the failover script can't allocate the " +
		"replacement IP. The 80% headroom rule applies.",
	Remediation: "Request a quota bump, OR free orphan reserved IPs " +
		"('doctl compute reserved-ip list --format IP,DropletID' — " +
		"empty DropletID means assigned to nothing).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.3"},
		"iso27001": {"A.8.6"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"account", "capacity", "networking"},
	Scanner: "account.ReservedIPQuotaHeadroom",
}

func AccountReservedIPQuotaHeadroom(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	used := len(g.ByType(docol.ReservedIPType))
	for _, a := range g.ByType(docol.AccountType) {
		limit, _ := a.Attributes["reserved_ip_limit"].(int)
		findings = append(findings, quotaHeadroom(CheckAccountReservedIPQuotaHeadroom, a, used, limit, "reserved IPs"))
	}
	return findings, nil
}

// ----- 5. monitoring alert coverage (4 basics) --------------------------

// The four standard ops-channel alert categories DO surfaces via
// v1/insights/droplet/*. Any production droplet fleet should have at
// least one enabled policy in each category.
var alertCoverageRequired = []struct {
	label      string
	typePrefix string
}{
	{"cpu", "v1/insights/droplet/cpu"},
	{"memory", "v1/insights/droplet/memory"},
	{"disk", "v1/insights/droplet/disk"},
	{"load", "v1/insights/droplet/load"},
}

var CheckAccountMonitoringAlertCoverage = compliancekit.Check{
	ID:           "do-account-monitoring-alert-coverage",
	Title:        "Account should have enabled alerts for CPU, memory, disk, and load",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "monitoring",
	ResourceType: docol.AccountType,
	Description: "Beyond 'at least one alert exists', SOC2 CC7.2 and ISO " +
		"A.8.16 expect coverage across the four primary droplet vitals: " +
		"CPU, memory, disk, and load. A monitoring posture missing any " +
		"of these leaves blind spots that page operators too late.",
	Remediation: "Create the missing alert types. Example for CPU: 'doctl " +
		"monitoring alert create --type v1/insights/droplet/cpu " +
		"--description \"high cpu\" --compare GreaterThan --value 80 " +
		"--window 5m --emails ops@example.com'. Repeat for memory, " +
		"disk, and load with thresholds appropriate to your workloads.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"monitoring", "alerting"},
	Scanner: "monitoring.AlertCoverage",
}

func AccountMonitoringAlertCoverage(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	accounts := g.ByType(docol.AccountType)
	if len(accounts) == 0 {
		return findings, nil
	}
	alerts := g.ByType(docol.AlertPolicyType)
	covered := map[string]bool{}
	for _, p := range alerts {
		enabled, _ := p.Attributes["enabled"].(bool)
		if !enabled {
			continue
		}
		at, _ := p.Attributes["alert_type"].(string)
		for _, req := range alertCoverageRequired {
			if strings.HasPrefix(at, req.typePrefix) {
				covered[req.label] = true
			}
		}
	}
	var missing []string
	for _, req := range alertCoverageRequired {
		if !covered[req.label] {
			missing = append(missing, req.label)
		}
	}
	for _, a := range accounts {
		f := newAccountFinding(CheckAccountMonitoringAlertCoverage, a)
		if len(missing) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("account %q: alert coverage complete (cpu, memory, disk, load)", a.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("account %q: missing alert coverage: %s", a.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. MFA required (manual-verify) ----------------------------------

var CheckAccountMFARequired = compliancekit.Check{
	ID:           "do-account-mfa-required",
	Title:        "Account must require two-factor authentication for all members",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "Mandatory 2FA across every team member is table stakes " +
		"for any audit framework (SOC2 CC6.1, ISO A.5.16, CIS 6.5). " +
		"DigitalOcean enforces this via the team settings UI but " +
		"does not expose enforcement state in the public API — every " +
		"audit therefore requires manual evidence: a screenshot of " +
		"the team Security page showing the toggle on plus a roster " +
		"of members with 2FA enabled. This finding records the control " +
		"gap so the auditor knows to gather that evidence.",
	Remediation: "Cloud Panel → Settings → Security → 'Require two-factor " +
		"authentication'. Toggle on. Confirm every team member has " +
		"2FA enrolled (Members tab → 2FA column). Record screenshot " +
		"evidence alongside this report.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.5.16", "A.5.17"},
		"cis-v8":   {"6.5"},
	},
	Tags:    []string{"account", "identity", "manual-verify"},
	Scanner: "account.MFARequired",
}

func AccountMFARequired(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		findings = append(findings,
			manualVerify(CheckAccountMFARequired, a,
				"2FA enforcement state",
				manualVerifyDashboard+"/account/security"))
	}
	return findings, nil
}

// ----- 7. API token rotation cadence (manual-verify) --------------------

var CheckAccountAPITokenRotation = compliancekit.Check{
	ID:           "do-account-api-token-rotation-cadence",
	Title:        "API tokens must be rotated on a documented cadence (≤90d)",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DO API tokens are long-lived bearer credentials. The DO " +
		"public API does not expose token creation dates, scopes, or " +
		"last-use time — the dashboard is the only audit surface. SOC2 " +
		"CC6.3 + ISO A.5.16 + CIS 5.4 each require documented rotation " +
		"intervals (typically ≤90 days) and revocation of unused tokens. " +
		"This finding records the control gap so the auditor knows to " +
		"gather rotation logs.",
	Remediation: "Cloud Panel → API → Tokens. Sort by 'Last Used'; revoke " +
		"any token unused for >30 days, and any token older than 90 " +
		"days regardless of last-use. Issue replacements via the same " +
		"page; update consumers; capture the before/after roster as " +
		"audit evidence.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.3"},
		"iso27001": {"A.5.16", "A.8.5"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"account", "credentials", "manual-verify"},
	Scanner: "account.APITokenRotation",
}

func AccountAPITokenRotation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		findings = append(findings,
			manualVerify(CheckAccountAPITokenRotation, a,
				"API token rotation cadence",
				manualVerifyDashboard+"/account/api/tokens"))
	}
	return findings, nil
}

// ----- 8. audit log retention (manual-verify) ---------------------------

var CheckAccountAuditLogRetention = compliancekit.Check{
	ID:           "do-account-audit-log-retention",
	Title:        "Account audit logs must be retained ≥90 days",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "Audit logs document every team-member action against " +
		"control-plane resources. DigitalOcean's audit log is available " +
		"only via the dashboard (no public API endpoint at the time of " +
		"writing) and the default retention is ≤30 days on most tiers. " +
		"SOC2 CC7.2, ISO A.8.15, and CIS 8.1 each require ≥90 days of " +
		"log retention with tamper-evident storage. This finding " +
		"records the control gap.",
	Remediation: "Cloud Panel → Settings → Audit Logs. Confirm logs are " +
		"enabled and retention is ≥90 days. If retention is below " +
		"policy, enable the audit-log-export integration (Splunk / " +
		"Datadog / S3) to extend retention beyond the in-platform " +
		"default. Capture configuration as audit evidence.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.1", "8.10"},
	},
	Tags:    []string{"account", "audit-trail", "manual-verify"},
	Scanner: "account.AuditLogRetention",
}

func AccountAuditLogRetention(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		findings = append(findings,
			manualVerify(CheckAccountAuditLogRetention, a,
				"audit-log retention ≥90d",
				manualVerifyDashboard+"/account/audit-logs"))
	}
	return findings, nil
}

// ----- 9. billing alert thresholds (manual-verify) ----------------------

var CheckAccountBillingAlertThresholds = compliancekit.Check{
	ID:           "do-account-billing-alert-thresholds",
	Title:        "Monthly billing alerts must be configured at documented thresholds",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DigitalOcean's billing-alerts surface is dashboard-only; " +
		"no public API exposes the configured monthly threshold or " +
		"recipient roster. An unaccompanied invoice doubling — typical " +
		"of a runaway autoscaler or unauthorized resource provisioning — " +
		"is a financial AND security signal. SOC2 A1.2 requires capacity " +
		"alerts that catch budget anomalies before billing close.",
	Remediation: "Cloud Panel → Settings → Billing → Alerts. Set monthly " +
		"alert at 80% and 100% of expected spend; route to finance + " +
		"engineering distribution lists, not a single inbox. Document " +
		"the threshold and recipients in the runbook.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"account", "billing", "manual-verify"},
	Scanner: "account.BillingAlertThresholds",
}

func AccountBillingAlertThresholds(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		findings = append(findings,
			manualVerify(CheckAccountBillingAlertThresholds, a,
				"billing alert thresholds + recipients",
				manualVerifyDashboard+"/account/billing"))
	}
	return findings, nil
}

// ----- 10. owner delegation policy (manual-verify) ----------------------

var CheckAccountOwnerDelegation = compliancekit.Check{
	ID:           "do-account-owner-delegation-policy",
	Title:        "Owner-delegation policy must be documented (bus-factor ≥2)",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DigitalOcean does not expose team-owner change history " +
		"or delegation procedures via API. A single owner = bus-factor " +
		"1 across billing, member-management, and account-deletion — " +
		"the highest-blast-radius operations on the platform. SOC2 " +
		"CC1.4 and ISO A.5.2 require segregation-of-duties + at least " +
		"one documented delegate.",
	Remediation: "Cloud Panel → Settings → Team → Members. Confirm ≥2 " +
		"members carry the 'Owner' role (or that an explicit succession " +
		"policy is recorded with co-administrator credentials). Document " +
		"the delegation procedure in the security runbook and review " +
		"quarterly.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4", "CC6.3"},
		"iso27001": {"A.5.2", "A.5.15"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"account", "bus-factor", "manual-verify"},
	Scanner: "account.OwnerDelegation",
}

func AccountOwnerDelegation(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		findings = append(findings,
			manualVerify(CheckAccountOwnerDelegation, a,
				"owner-delegation policy + member roster",
				manualVerifyDashboard+"/account/team"))
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckAccountStatusMessageClean, AccountStatusMessageClean)
	compliancekit.Register(CheckAccountDropletQuotaHeadroom, AccountDropletQuotaHeadroom)
	compliancekit.Register(CheckAccountVolumeQuotaHeadroom, AccountVolumeQuotaHeadroom)
	compliancekit.Register(CheckAccountReservedIPQuotaHeadroom, AccountReservedIPQuotaHeadroom)
	compliancekit.Register(CheckAccountMonitoringAlertCoverage, AccountMonitoringAlertCoverage)
	compliancekit.Register(CheckAccountMFARequired, AccountMFARequired)
	compliancekit.Register(CheckAccountAPITokenRotation, AccountAPITokenRotation)
	compliancekit.Register(CheckAccountAuditLogRetention, AccountAuditLogRetention)
	compliancekit.Register(CheckAccountBillingAlertThresholds, AccountBillingAlertThresholds)
	compliancekit.Register(CheckAccountOwnerDelegation, AccountOwnerDelegation)
}
