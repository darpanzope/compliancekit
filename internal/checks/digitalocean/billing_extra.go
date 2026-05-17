package digitalocean

import (
	"context"
	"fmt"
	"strings"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 8 — billing exposure + tagging hygiene. Three real-data
// checks read tags / status / created_at across resources; seven
// manual-verify checks point at billing controls DO doesn't expose
// via the API.

const billingDashboardURL = "https://cloud.digitalocean.com/account/billing"

func newBillingFinding(check core.Check, r core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: r.Ref(),
		Tags:     check.Tags,
	}
}

func billingManualVerify(check core.Check, r core.Resource, control string) core.Finding {
	f := newBillingFinding(check, r)
	f.Status = core.StatusError
	f.Message = fmt.Sprintf("%s %q: %s — verify in dashboard: %s",
		r.Type, r.Name, control, billingDashboardURL)
	return f
}

// firstAccount returns the AccountType anchor, or zero value if none.
func firstAccount(g *core.ResourceGraph) core.Resource {
	accounts := g.ByType(docol.AccountType)
	if len(accounts) == 0 {
		return core.Resource{}
	}
	return accounts[0]
}

// ----- 1. droplet stopped > 30d --------------------------------------

var CheckDropletStoppedTooLong = core.Check{
	ID:           "do-droplet-stopped-too-long",
	Title:        "Stopped droplets accumulate cost without serving traffic",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "DO bills droplets in 'off' state at standard rate. A " +
		"droplet powered off > 30 days is either staging-leftover or " +
		"a forgotten experiment. Either way: not generating value.",
	Remediation: "Audit: `doctl compute droplet list --format ID,Name,Status,Created`. " +
		"For genuinely orphaned droplets, snapshot then destroy: " +
		"`doctl compute droplet-action snapshot <id> --snapshot-name backup` " +
		"then `doctl compute droplet delete <id> --force`.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"droplets", "cost", "hygiene"},
	Scanner: "droplets.StoppedTooLong",
}

func DropletStoppedTooLong(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	const stopThreshold = 30 * 24 * time.Hour
	findings := []core.Finding{}
	now := time.Now().UTC()
	for _, d := range g.ByType(docol.DropletType) {
		status, _ := d.Attributes["status"].(string)
		if status != "off" {
			continue
		}
		created, _ := d.Attributes["created_at"].(time.Time)
		f := newBillingFinding(CheckDropletStoppedTooLong, d)
		if !created.IsZero() && now.Sub(created) > stopThreshold {
			days := int(now.Sub(created).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: off for %d days", d.Name, days)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: off but recent", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. project must declare a purpose -----------------------------

var CheckProjectPurpose = core.Check{
	ID:           "do-project-no-purpose",
	Title:        "Projects must declare a non-default purpose",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "projects",
	ResourceType: docol.ProjectType,
	Description: "DO projects carry a 'purpose' field used by billing " +
		"breakouts. Default purpose ('Service or API') is the catch-all " +
		"new projects ship with — empty or default purpose makes per-" +
		"project cost attribution noise.",
	Remediation: "`doctl projects update <id> --purpose='Production " +
		"Web Application'`. Conventional purposes: Web Application, " +
		"Operational, Trying out DigitalOcean, Class project / " +
		"educational purposes.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"projects", "billing", "tagging"},
	Scanner: "projects.Purpose",
}

func ProjectPurpose(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, p := range g.ByType(docol.ProjectType) {
		purpose, _ := p.Attributes["purpose"].(string)
		f := newBillingFinding(CheckProjectPurpose, p)
		switch strings.TrimSpace(purpose) {
		case "", "Service or API":
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("project %q: purpose=%q (default / empty)", p.Name, purpose)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("project %q: purpose=%q", p.Name, purpose)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. droplet over-provisioned by ≥6 months -------------------

var CheckDropletAgedOversized = core.Check{
	ID:           "do-droplet-aged-no-rightsizing",
	Title:        "Droplets >180 days old should be reviewed for right-sizing",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "Droplet sizes commonly outgrow or undergrow the workload " +
		"over 6 months. DO doesn't auto-rightsize. A periodic review " +
		"of long-running droplets vs their CPU/memory utilization " +
		"history catches both under- and over-provisioning before they " +
		"either fail SLO or burn budget.",
	Remediation: "Review the monitoring dashboard for sustained CPU + " +
		"memory utilization over 30 days. If sustained < 30%, resize " +
		"down: `doctl compute droplet-action resize <id> " +
		"--size s-1vcpu-2gb`. If > 80%, resize up.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"droplets", "rightsizing", "cost"},
	Scanner: "droplets.AgedOversized",
}

func DropletAgedOversized(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	const reviewThreshold = 180 * 24 * time.Hour
	findings := []core.Finding{}
	now := time.Now().UTC()
	for _, d := range g.ByType(docol.DropletType) {
		created, _ := d.Attributes["created_at"].(time.Time)
		f := newBillingFinding(CheckDropletAgedOversized, d)
		if !created.IsZero() && now.Sub(created) > reviewThreshold {
			days := int(now.Sub(created).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("droplet %q: %d days old — review sizing vs monitoring data", d.Name, days)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("droplet %q: under review threshold", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers for the manual-verify family --------------------------

type manualCheckSpec struct {
	id, title, scanner string
	severity           core.Severity
	soc2, iso, cis     []string
	tags               []string
	descr              string
	remed              string
}

func makeManualCheck(spec manualCheckSpec) core.Check {
	return core.Check{
		ID:           spec.id,
		Title:        spec.title,
		Severity:     spec.severity,
		Provider:     "digitalocean",
		Service:      "billing",
		ResourceType: docol.AccountType,
		Description:  spec.descr,
		Remediation:  spec.remed,
		Frameworks: map[string][]string{
			"soc2":     spec.soc2,
			"iso27001": spec.iso,
			"cis-v8":   spec.cis,
		},
		Tags:    spec.tags,
		Scanner: spec.scanner,
	}
}

// Account-anchored manual checks share the same shape; the runner is
// parameterized by the (check, control-label) tuple.
func runManualBilling(check core.Check, control string, g *core.ResourceGraph) []core.Finding {
	acct := firstAccount(g)
	if acct.ID == "" {
		return nil
	}
	return []core.Finding{billingManualVerify(check, acct, control)}
}

// ----- 4-10. manual-verify family -----------------------------------

var (
	CheckBillingMonthlyAlertReview = makeManualCheck(manualCheckSpec{
		id: "do-billing-monthly-alert-review", title: "Monthly billing alert thresholds + recipients reviewed",
		severity: core.SeverityMedium, soc2: []string{"A1.2"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "manual-verify"}, scanner: "billing.MonthlyAlertReview",
		descr: "Billing alert thresholds + recipient roster need quarterly " +
			"review — costs grow, headcount changes, alerts go stale. DO " +
			"doesn't expose the alert config via API.",
		remed: "Quarterly: open the billing dashboard, confirm thresholds " +
			"still match the budget, confirm distros still resolve.",
	})

	CheckBillingPaymentMethodValid = makeManualCheck(manualCheckSpec{
		id: "do-billing-payment-method-valid", title: "Primary payment method must not be near expiry",
		severity: core.SeverityHigh, soc2: []string{"A1.2"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "manual-verify"}, scanner: "billing.PaymentMethodValid",
		descr: "An expired card pauses the account; account status drops to " +
			"warning. DO doesn't expose card-expiry via API.",
		remed: "Quarterly: confirm the card on file has ≥3 months until expiry. " +
			"Add a backup method.",
	})

	CheckBillingCostBreakoutDocumented = makeManualCheck(manualCheckSpec{
		id: "do-billing-cost-breakout-documented", title: "Per-project cost breakout must be exportable monthly",
		severity: core.SeverityLow, soc2: []string{"A1.2"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "manual-verify"}, scanner: "billing.CostBreakoutDocumented",
		descr: "DO exposes invoices via API but not per-project cost " +
			"breakout; finance teams typically need that for chargeback.",
		remed: "Monthly: pull the invoice CSV from the dashboard, sort by " +
			"project tag, archive in finance shared drive.",
	})

	CheckBillingReservedCommitments = makeManualCheck(manualCheckSpec{
		id: "do-billing-reserved-commitments-reviewed", title: "DO Reserved (1y/3y) commitments reviewed against utilization",
		severity: core.SeverityLow, soc2: []string{"A1.1"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "manual-verify"}, scanner: "billing.ReservedCommitments",
		descr: "DO reserved pricing is opt-in; without periodic review you " +
			"either miss savings or over-commit on workloads that have moved.",
		remed: "Quarterly: compare reserved-instance attribution vs " +
			"actual droplet usage. Cancel under-utilized reservations.",
	})

	CheckBillingDatabasePauseAudit = makeManualCheck(manualCheckSpec{
		id: "do-billing-database-pause-audit", title: "Paused managed databases are still billed; audit retention",
		severity: core.SeverityMedium, soc2: []string{"A1.1"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "manual-verify"}, scanner: "billing.DatabasePauseAudit",
		descr: "DO managed databases bill in 'offline' (paused) state at " +
			"standard rate. Pause-and-forget is a common waste pattern.",
		remed: "Quarterly: list `doctl databases list`; for any in offline " +
			"state, decide resume vs delete.",
	})

	CheckBillingSnapshotRetention = makeManualCheck(manualCheckSpec{
		id: "do-billing-snapshot-retention-policy", title: "Snapshot retention policy must be documented + enforced",
		severity: core.SeverityLow, soc2: []string{"A1.1", "CC9.1"}, iso: []string{"A.5.34"}, cis: []string{"11.2"},
		tags: []string{"billing", "snapshots", "manual-verify"}, scanner: "billing.SnapshotRetention",
		descr: "DO snapshots accumulate forever at $0.05/GB/month. Without a " +
			"documented retention SLA, the snapshot bill grows unbounded.",
		remed: "Document retention (e.g. 90d for ad-hoc, 1y for release " +
			"baselines). Implement via cron: `doctl compute snapshot list " +
			"--format ID,Created` + age-based delete.",
	})

	CheckBillingCDNTrafficCost = makeManualCheck(manualCheckSpec{
		id: "do-billing-cdn-traffic-cost", title: "CDN traffic cost must be tracked monthly",
		severity: core.SeverityLow, soc2: []string{"A1.1"}, iso: []string{"A.5.30"}, cis: []string{"12.1"},
		tags: []string{"billing", "cdn", "manual-verify"}, scanner: "billing.CDNTrafficCost",
		descr: "DO Spaces CDN bills egress separately from origin storage. " +
			"A misconfigured cache (TTL=0, no Cache-Control headers) " +
			"multiplies origin hits + CDN cost.",
		remed: "Monthly: review CDN bandwidth in the billing breakout. If " +
			"unexpected: audit cache headers + TTL on the CDN config.",
	})
)

func init() {
	core.Register(CheckDropletStoppedTooLong, DropletStoppedTooLong)
	core.Register(CheckProjectPurpose, ProjectPurpose)
	core.Register(CheckDropletAgedOversized, DropletAgedOversized)
	core.Register(CheckBillingMonthlyAlertReview, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingMonthlyAlertReview, "monthly billing alert thresholds + recipients", g), nil
	})
	core.Register(CheckBillingPaymentMethodValid, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingPaymentMethodValid, "primary payment method expiry", g), nil
	})
	core.Register(CheckBillingCostBreakoutDocumented, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingCostBreakoutDocumented, "per-project cost breakout export", g), nil
	})
	core.Register(CheckBillingReservedCommitments, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingReservedCommitments, "reserved-commitment utilization review", g), nil
	})
	core.Register(CheckBillingDatabasePauseAudit, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingDatabasePauseAudit, "paused database audit", g), nil
	})
	core.Register(CheckBillingSnapshotRetention, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingSnapshotRetention, "snapshot retention policy", g), nil
	})
	core.Register(CheckBillingCDNTrafficCost, func(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
		return runManualBilling(CheckBillingCDNTrafficCost, "CDN traffic cost tracking", g), nil
	})
}
