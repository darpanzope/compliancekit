package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

var CheckAppNoPlainEnvs = core.Check{
	ID:           "do-app-plain-env-vars",
	Title:        "App Platform apps must mark secrets as SECRET type",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform variable definitions have a type field: " +
		"GENERAL (plaintext, visible in spec) or SECRET (encrypted at " +
		"rest, never returned). Storing API keys / DB passwords / OAuth " +
		"secrets as GENERAL plaintext leaks them to anyone with " +
		"app:read permission on the project. Mark every credential " +
		"SECRET.",
	Remediation: "Edit the app spec, change type from GENERAL to SECRET " +
		"on every credential-bearing env var. Either through the DO " +
		"control panel or 'doctl apps spec' + 'doctl apps update'. " +
		"After the change, rotate any credential that was previously " +
		"plaintext -- assume it was logged somewhere.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.5.17"},
		"cis-v8":   {"3.1", "3.11"},
	},
	Tags:    []string{"app-platform", "secrets"},
	Scanner: "apps.NoPlainEnvs",
}

func AppNoPlainEnvs(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		n, _ := a.Attributes["plain_env_count"].(int)
		f := core.Finding{
			CheckID:  CheckAppNoPlainEnvs.ID,
			Severity: CheckAppNoPlainEnvs.Severity,
			Resource: a.Ref(),
			Tags:     CheckAppNoPlainEnvs.Tags,
		}
		// App-level envs are commonly non-secret (PORT, NODE_ENV).
		// Flag only when there are more than 5 -- empirically the
		// signal threshold; below that, the operator has likely
		// classified intentionally.
		if n > 5 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d plaintext env vars (review for secrets)", a.Name, n)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d plaintext env vars", a.Name, n)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckAppCustomDomain = core.Check{
	ID:           "do-app-no-custom-domain",
	Title:        "Production App Platform apps should have a custom domain",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform apps default to the ondigitalocean.app " +
		"subdomain. Production apps should serve from a custom domain " +
		"for branding, certificate ownership, and DNS-level traffic " +
		"control. No custom domain is fine for dev/preview deployments " +
		"but a posture-anti-pattern for prod.",
	Remediation: "Add a domain in the App spec under 'domains:'. Point " +
		"your DNS at the app's CNAME and DO will provision a managed " +
		"Let's Encrypt cert automatically.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"app-platform", "branding"},
	Scanner: "apps.CustomDomain",
}

func AppCustomDomain(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		has, _ := a.Attributes["has_custom_domains"].(bool)
		f := core.Finding{
			CheckID:  CheckAppCustomDomain.ID,
			Severity: CheckAppCustomDomain.Severity,
			Resource: a.Ref(),
			Tags:     CheckAppCustomDomain.Tags,
		}
		if has {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: custom domain(s) configured", a.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: only the default ondigitalocean.app domain", a.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckAppDomainTLSVersion = core.Check{
	ID:           "do-app-domain-weak-tls",
	Title:        "App Platform custom domains must require TLS 1.2 or higher",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform domains expose a minimum_tls_version " +
		"setting per domain. Default at v1.2 today; explicitly setting " +
		"\"1.2\" or \"1.3\" makes the policy auditable. Empty or " +
		"\"1.0\"/\"1.1\" is the regression-prone shape.",
	Remediation: "In each domain block under the app spec, set " +
		"minimum_tls_version: \"1.2\" (or \"1.3\" for modern apps with " +
		"no legacy client requirements). Apply via 'doctl apps update'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"app-platform", "tls"},
	Scanner: "apps.DomainTLSVersion",
}

func AppDomainTLSVersion(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		domains, _ := a.Attributes["domains"].([]map[string]any)
		if len(domains) == 0 {
			continue
		}
		f := core.Finding{
			CheckID:  CheckAppDomainTLSVersion.ID,
			Severity: CheckAppDomainTLSVersion.Severity,
			Resource: a.Ref(),
			Tags:     CheckAppDomainTLSVersion.Tags,
		}
		weak := []string{}
		for _, d := range domains {
			tls, _ := d["minimum_tls_version"].(string)
			domName, _ := d["domain"].(string)
			if tls == "1.0" || tls == "1.1" {
				weak = append(weak, domName+":"+tls)
			}
		}
		if len(weak) > 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: %d domain(s) on weak TLS: %v", a.Name, len(weak), weak)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: %d domain(s), all TLS >= 1.2", a.Name, len(domains))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckAppHasAlerts = core.Check{
	ID:           "do-app-no-alerts",
	Title:        "App Platform apps should have alerts configured",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "Alerts on App Platform apps fire on deploy failure, " +
		"crash loop, or restart rate. Without them an app can fail " +
		"silently with the only signal being the user complaint. " +
		"Configure at least DEPLOYMENT_FAILED + RESTART_COUNT.",
	Remediation: "Add alerts to the app spec: 'alerts: - rule: " +
		"DEPLOYMENT_FAILED' etc. The DO docs list the available rule " +
		"types; pair with a notification destination (slack, email).",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"app-platform", "alerting"},
	Scanner: "apps.HasAlerts",
}

func AppHasAlerts(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		has, _ := a.Attributes["has_alerts"].(bool)
		f := core.Finding{
			CheckID:  CheckAppHasAlerts.ID,
			Severity: CheckAppHasAlerts.Severity,
			Resource: a.Ref(),
			Tags:     CheckAppHasAlerts.Tags,
		}
		if has {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: alerts configured", a.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: no alerts configured", a.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckAppInVPC = core.Check{
	ID:           "do-app-no-vpc",
	Title:        "App Platform apps should bind to a VPC",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "apps",
	ResourceType: docol.AppType,
	Description: "App Platform supports binding the egress side of an app " +
		"to a specific VPC so the app can reach private droplets or " +
		"managed DBs via private addressing. Apps without a VPC bind " +
		"can only reach public endpoints -- forcing prod DB " +
		"connections through the public internet.",
	Remediation: "Add a vpc: block to the app spec naming the target " +
		"VPC. Applies on next deployment.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2"},
	},
	Tags:    []string{"app-platform", "network"},
	Scanner: "apps.InVPC",
}

func AppInVPC(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AppType) {
		in, _ := a.Attributes["in_vpc"].(bool)
		f := core.Finding{
			CheckID:  CheckAppInVPC.ID,
			Severity: CheckAppInVPC.Severity,
			Resource: a.Ref(),
			Tags:     CheckAppInVPC.Tags,
		}
		if in {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("app %q: bound to VPC", a.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("app %q: no VPC binding (egress over public internet)", a.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckAppNoPlainEnvs, AppNoPlainEnvs)
	core.Register(CheckAppCustomDomain, AppCustomDomain)
	core.Register(CheckAppDomainTLSVersion, AppDomainTLSVersion)
	core.Register(CheckAppHasAlerts, AppHasAlerts)
	core.Register(CheckAppInVPC, AppInVPC)
}
