package digitalocean

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.19 phase 5 — App Platform depth: alert coverage on every service,
// healthcheck coverage, log forwarding, deploy-on-push hygiene,
// tier-vs-environment, managed-database posture, regional pinning,
// and manual-verify gaps (build-time secret scanning, CDN integration,
// custom-domain cert hygiene).
//
// Most checks read attributes from the v0.19 phase 5 collector
// extension. Manual-verify checks fire when DO does not surface the
// underlying state.

func newAppFinding(check core.Check, app core.Resource) core.Finding {
	return core.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Resource: app.Ref(),
		Tags:     check.Tags,
	}
}

func appManualVerify(check core.Check, app core.Resource, control, url string) core.Finding {
	f := newAppFinding(check, app)
	f.Status = core.StatusError
	f.Message = fmt.Sprintf("app %q: %s — DO API does not expose this state; verify at %s",
		app.Name, control, url)
	return f
}

// ----- 1. every service must have a healthcheck -----------------------

var CheckAppServicesHealthcheck = core.Check{
	ID:           "do-app-services-no-healthcheck",
	Title:        "Every App Platform service must declare a HealthCheck",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "Without a HealthCheck declaration App Platform falls " +
		"back to TCP-port liveness — a hung process that still holds the " +
		"socket is treated as healthy. SOC2 A1.2 and ISO A.8.16 expect " +
		"explicit liveness probes on production services.",
	Remediation: "Add a http_path-based HealthCheck per service in the " +
		"app spec: 'health_check: {http_path: /healthz}'. Pair with a " +
		"liveness endpoint that exercises critical dependencies " +
		"(database connection, downstream API).",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"apps", "healthcheck"},
	Scanner: "apps.ServicesHealthcheck",
}

func AppServicesHealthcheck(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		total, _ := a.Attributes["service_count"].(int)
		if total == 0 {
			continue
		}
		covered, _ := a.Attributes["services_with_healthcheck"].(int)
		f := newAppFinding(CheckAppServicesHealthcheck, a)
		if covered == total {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d/%d services have healthchecks", a.Name, covered, total)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d/%d services missing healthchecks", a.Name, total-covered, total)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 2. log forwarding configured on every service -----------------

var CheckAppServicesLogDest = core.Check{
	ID:           "do-app-services-no-log-destinations",
	Title:        "App Platform services should forward logs to a long-retention sink",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform's built-in log viewer retains ~7 days of " +
		"logs — insufficient for audit (SOC2 CC7.2 expects ≥90d). The " +
		"app spec's 'log_destinations:' block forwards to Papertrail, " +
		"Datadog, Logtail, or a generic OpenSearch endpoint.",
	Remediation: "Add a log_destinations block per service: " +
		"'log_destinations: [{name: prod, datadog: {api_key: $DD_KEY, " +
		"endpoint: ...}}]'. Pair with a sink that meets the retention " +
		"SLA.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"apps", "logging", "retention"},
	Scanner: "apps.ServicesLogDest",
}

func AppServicesLogDest(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		total, _ := a.Attributes["service_count"].(int)
		if total == 0 {
			continue
		}
		covered, _ := a.Attributes["services_with_log_dest"].(int)
		f := newAppFinding(CheckAppServicesLogDest, a)
		if covered == total {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d/%d services forward logs", a.Name, covered, total)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d/%d services have no log destination", a.Name, total-covered, total)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 3. per-service alert policies -----------------------------------

var CheckAppServicesAlerts = core.Check{
	ID:           "do-app-services-no-service-alerts",
	Title:        "App Platform services should each declare their own alerts",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App-level alerts (covered by do-app-no-alerts) catch " +
		"deploy + domain events. Service-level alerts catch per-service " +
		"behavior: CPU > X, restart count > Y, request latency > Z. " +
		"SOC2 CC7.2 expects per-component monitoring; a single app-level " +
		"alert isn't sufficient for multi-service apps.",
	Remediation: "Add 'alerts:' to each service spec with at minimum " +
		"DEPLOYMENT_FAILED + CPU_UTILIZATION + MEM_UTILIZATION rules.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"apps", "alerts", "per-service"},
	Scanner: "apps.ServicesAlerts",
}

func AppServicesAlerts(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		total, _ := a.Attributes["service_count"].(int)
		if total == 0 {
			continue
		}
		covered, _ := a.Attributes["services_with_alerts"].(int)
		f := newAppFinding(CheckAppServicesAlerts, a)
		if covered == total {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d/%d services have per-service alerts", a.Name, covered, total)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d/%d services have no per-service alerts", a.Name, total-covered, total)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 4. tier appropriate for production ------------------------------

// appBelowProdTiers are tier_slug values that ship without HA + with
// shared infrastructure — fine for prototypes, wrong for prod.
var appBelowProdTiers = []string{"basic-xxs", "basic-xs", "basic-s", "basic-m"}

var CheckAppTierProdGrade = core.Check{
	ID:           "do-app-tier-below-production",
	Title:        "Apps tagged production should run on professional tier or above",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "Basic-tier App Platform shares droplet pools and lacks " +
		"the autoscaling + per-tenant isolation production typically " +
		"needs. SOC2 A1.1 + ISO A.8.14 expect production capacity " +
		"planning; the tier slug is the simplest proxy.",
	Remediation: "Bump to a professional tier: 'doctl apps update <id> " +
		"--spec spec.yaml' with 'tier_slug: professional-xs' (or " +
		"higher). Migration is online; expect a redeploy.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.8.14"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"apps", "tier", "capacity"},
	Scanner: "apps.TierProdGrade",
}

func AppTierProdGrade(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		tier, _ := a.Attributes["tier_slug"].(string)
		f := newAppFinding(CheckAppTierProdGrade, a)
		below := false
		for _, t := range appBelowProdTiers {
			if tier == t {
				below = true
				break
			}
		}
		if below {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: tier=%q below production grade", a.Name, tier)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: tier=%q acceptable for production", a.Name, tier)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 5. databases must be production-marked when present -----------

var CheckAppDatabaseProduction = core.Check{
	ID:           "do-app-database-not-production-marked",
	Title:        "App Platform databases must be marked production",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform databases default to dev_database = true " +
		"(shared/free tier). production: true upgrades to a dedicated " +
		"managed cluster with HA + automated backups. Production " +
		"workloads on dev databases lose data on any control-plane " +
		"event.",
	Remediation: "In the app spec, set 'databases: [{name: ..., engine: " +
		"PG, production: true, cluster_name: <managed-db-cluster>}]'. " +
		"Plan a cutover: dev DBs are not backed up, so manual dump+restore " +
		"to the new cluster is required.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC9.1"},
		"iso27001": {"A.8.13"},
		"cis-v8":   {"11.2"},
	},
	Tags:    []string{"apps", "database", "production"},
	Scanner: "apps.DatabaseProduction",
}

func AppDatabaseProduction(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		total, _ := a.Attributes["database_count"].(int)
		if total == 0 {
			continue
		}
		managed, _ := a.Attributes["managed_db_count"].(int)
		f := newAppFinding(CheckAppDatabaseProduction, a)
		if managed == total {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d/%d databases marked production", a.Name, managed, total)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d/%d databases NOT production (dev/shared)", a.Name, total-managed, total)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 6. deploy-on-push without protection (manual-verify) ----------

var CheckAppDeployOnPushProtection = core.Check{
	ID:           "do-app-deploy-on-push-no-branch-protection",
	Title:        "Deploy-on-push services must target protected branches",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "Deploy-on-push means a git push to the source branch " +
		"triggers a production deployment. Without branch protection " +
		"(required reviews, status checks) on the source side, any " +
		"git collaborator can ship to production without review. The " +
		"App spec carries the branch name but the GitHub/GitLab " +
		"branch-protection state is on the source side, not DO's API.",
	Remediation: "GitHub: Settings → Branches → add a protection rule on " +
		"the deploy branch (require ≥1 review, require status checks). " +
		"GitLab: Settings → Repository → Protected Branches. Document " +
		"the deploy branch + protection rules in the runbook.",
	Frameworks: map[string][]string{
		"soc2":     {"CC8.1"},
		"iso27001": {"A.8.32"},
		"cis-v8":   {"4.1", "16.1"},
	},
	Tags:    []string{"apps", "deploy-on-push", "manual-verify"},
	Scanner: "apps.DeployOnPushProtection",
}

func AppDeployOnPushProtection(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		dop, _ := a.Attributes["services_deploy_on_push"].(int)
		if dop == 0 {
			continue
		}
		findings = append(findings,
			appManualVerify(CheckAppDeployOnPushProtection, a,
				fmt.Sprintf("%d service(s) deploy-on-push — verify source branch protection", dop),
				"https://github.com/settings"))
	}
	return findings, nil
}

// ----- 7. domain TLS minimum 1.3 ---------------------------------------

var CheckAppDomainTLS13 = core.Check{
	ID:           "do-app-domain-tls-below-1-3",
	Title:        "App Platform custom domains should enforce TLS 1.3",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "Existing do-app-domain-weak-tls flags TLS < 1.2. v0.19 " +
		"phase 5 raises the floor to 1.3 for production-grade domains. " +
		"TLS 1.2 remains supported but 1.3 is the current state of the " +
		"art (forward-secrecy by default, fewer cipher choices, " +
		"mandatory AEAD).",
	Remediation: "Update the App spec domain block: " +
		"'domains: [{domain: ..., minimum_tls_version: \"1.3\"}]'. " +
		"Verify clients don't break — TLS 1.3 is universally supported " +
		"across browsers + tools released after 2020.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"apps", "tls", "domain"},
	Scanner: "apps.DomainTLS13",
}

func AppDomainTLS13(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		raw, _ := a.Attributes["domains"].([]map[string]any)
		if len(raw) == 0 {
			continue
		}
		var below []string
		for _, d := range raw {
			tls, _ := d["minimum_tls_version"].(string)
			if tls != "1.3" {
				domain, _ := d["domain"].(string)
				below = append(below, fmt.Sprintf("%s=%s", domain, tls))
			}
		}
		f := newAppFinding(CheckAppDomainTLS13, a)
		if len(below) == 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: all %d domain(s) at TLS 1.3", a.Name, len(raw))
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: domains below TLS 1.3: %s", a.Name, strings.Join(below, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- 8. manual: build-time secret scanning --------------------------

var CheckAppBuildSecretScan = core.Check{
	ID:           "do-app-build-secret-scan",
	Title:        "App Platform builds must scan for committed secrets",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "DO App Platform does not run secret-scanning as part " +
		"of the build pipeline. A secret committed to the source repo " +
		"becomes part of every deployed image, and is recoverable from " +
		"the build cache for the lifetime of the cache. SOC2 CC6.7 " +
		"requires credential hygiene; verify a pre-commit or CI " +
		"step (gitleaks, trufflehog) runs against every PR.",
	Remediation: "Add a CI step on the source repo BEFORE the DO build " +
		"trigger: run 'gitleaks detect' or 'trufflehog filesystem .' " +
		"and fail the CI on findings. Block deploy-on-push to apps " +
		"whose CI lacks this gate.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.5"},
		"cis-v8":   {"16.4"},
	},
	Tags:    []string{"apps", "secret-scan", "manual-verify"},
	Scanner: "apps.BuildSecretScan",
}

func AppBuildSecretScan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		findings = append(findings,
			appManualVerify(CheckAppBuildSecretScan, a,
				"CI-side secret scanning gate",
				"https://github.com/gitleaks/gitleaks"))
	}
	return findings, nil
}

// ----- 9. manual: domain cert rotation -------------------------------

var CheckAppDomainCertRotation = core.Check{
	ID:           "do-app-domain-cert-rotation",
	Title:        "Custom-domain certs must auto-renew (Let's Encrypt or uploaded with auto-rotation)",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform Let's Encrypt certs auto-renew. Uploaded " +
		"certs do not — they expire silently and break HTTPS for the " +
		"custom domain. The DO API does not expose 'is this cert " +
		"DO-managed or uploaded' on a custom domain at runtime; the " +
		"operator must confirm via the dashboard or by issuing every " +
		"cert through Let's Encrypt at create time.",
	Remediation: "Either: (1) ensure every custom domain uses Let's " +
		"Encrypt — declare the domain in the app spec without a cert_id, " +
		"which triggers DO-managed Let's Encrypt. (2) For uploaded " +
		"certs, set a renewal calendar reminder ≥30d before expiry.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"apps", "tls", "cert-rotation", "manual-verify"},
	Scanner: "apps.DomainCertRotation",
}

func AppDomainCertRotation(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		hasDomains, _ := a.Attributes["has_custom_domains"].(bool)
		if !hasDomains {
			continue
		}
		findings = append(findings,
			appManualVerify(CheckAppDomainCertRotation, a,
				"custom-domain cert provenance (DO-managed vs uploaded)",
				"https://cloud.digitalocean.com/apps"))
	}
	return findings, nil
}

// ----- 10. manual: CDN attachment for static sites --------------------

var CheckAppCDNAttachment = core.Check{
	ID:           "do-app-cdn-attachment",
	Title:        "Public-facing apps should consider DO Spaces CDN for static asset delivery",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform serves static assets directly from the " +
		"app container, charging full bandwidth + CPU. Offloading to " +
		"a Spaces+CDN attachment cuts cost + latency. The App spec " +
		"doesn't carry CDN integration state, so this is manual.",
	Remediation: "Move static assets to a Spaces bucket; enable the " +
		"CDN attachment on the bucket (do-cdn-no-custom-domain check " +
		"covers the CDN side). Update the app to reference the CDN " +
		"endpoint for asset URLs.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1"},
		"iso27001": {"A.5.30"},
		"cis-v8":   {"12.1"},
	},
	Tags:    []string{"apps", "cdn", "performance", "manual-verify"},
	Scanner: "apps.CDNAttachment",
}

func AppCDNAttachment(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		findings = append(findings,
			appManualVerify(CheckAppCDNAttachment, a,
				"Spaces+CDN integration for static assets",
				"https://docs.digitalocean.com/products/spaces/how-to/enable-cdn/"))
	}
	return findings, nil
}

func init() {
	core.Register(CheckAppServicesHealthcheck, AppServicesHealthcheck)
	core.Register(CheckAppServicesLogDest, AppServicesLogDest)
	core.Register(CheckAppServicesAlerts, AppServicesAlerts)
	core.Register(CheckAppTierProdGrade, AppTierProdGrade)
	core.Register(CheckAppDatabaseProduction, AppDatabaseProduction)
	core.Register(CheckAppDeployOnPushProtection, AppDeployOnPushProtection)
	core.Register(CheckAppDomainTLS13, AppDomainTLS13)
	core.Register(CheckAppBuildSecretScan, AppBuildSecretScan)
	core.Register(CheckAppDomainCertRotation, AppDomainCertRotation)
	core.Register(CheckAppCDNAttachment, AppCDNAttachment)
}
