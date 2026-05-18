package digitalocean

import (
	"context"
	"fmt"
	"strings"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// eolEngineVersions are engine versions DO still accepts at create
// time but that are upstream-EOL. Running on these means missing
// security patches that won't ship to your cluster.
//
// Updated periodically; the postgres 13 / mysql 5.7 entries reflect
// the upstream EOL dates known at 2026-05.
var eolEngineVersions = map[string]bool{
	"pg:11":     true,
	"pg:12":     true,
	"pg:13":     true,
	"mysql:5.7": true,
	"redis:6":   true,
	"mongodb:4": true,
	"mongodb:5": true,
}

// firewallRulesOf reads the per-DB firewall rules slice. Returns
// nil if the collector couldn't fetch (no permission, etc.).
func firewallRulesOf(d compliancekit.Resource) []map[string]any {
	v, _ := d.Attributes["firewall_rules"].([]map[string]any)
	return v
}

// CheckDBHasFirewallRules requires the DB have at least one
// trusted-source rule. An empty list means the cluster is
// reachable from any source the public endpoint allows.
var CheckDBHasFirewallRules = compliancekit.Check{
	ID:           "do-db-no-firewall-rules",
	Title:        "Managed databases should have at least one trusted source",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "DO managed databases default to a public hostname + " +
		"port. The trusted-sources allowlist (DatabaseFirewallRule) is " +
		"what restricts inbound. An empty list means the DB is open to " +
		"every IP the DO platform accepts -- effectively the public " +
		"internet, modulo TLS + password.",
	Remediation: "Restrict to your droplet, K8s cluster, or tag: " +
		"'doctl databases firewalls append <db-id> --rule droplet:<id>' " +
		"(or 'tag:<tag>', 'k8s:<cluster-id>', or 'ip_addr:<cidr>').",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"3.3", "12.2"},
	},
	Tags:    []string{"database", "network-exposure"},
	Scanner: "databases.HasFirewallRules",
}

func DBHasFirewallRules(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		count, _ := d.Attributes["firewall_rule_count"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckDBHasFirewallRules.ID,
			Severity: CheckDBHasFirewallRules.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBHasFirewallRules.Tags,
		}
		if count > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: %d trusted source(s)", d.Name, count)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: no trusted-sources allowlist (open to platform)", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBFirewallNoPublicCIDR forbids 0.0.0.0/0 or ::/0 in the
// trusted-sources list. Those would be the same as no rules at
// all but worse because they look intentional.
var CheckDBFirewallNoPublicCIDR = compliancekit.Check{
	ID:           "do-db-firewall-includes-public",
	Title:        "Managed databases must not allow public CIDRs in trusted sources",
	Severity:     compliancekit.SeverityCritical,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "A trusted-source rule of type ip_addr with value " +
		"0.0.0.0/0 or ::/0 is the explicit shape of 'allow the entire " +
		"internet.' This is the catastrophic database misconfiguration; " +
		"it leaves TLS + password as the only defense against everyone " +
		"who can find your hostname (which is on a predictable " +
		"do-managed namespace).",
	Remediation: "Remove the public rule: 'doctl databases firewalls " +
		"remove <db-id> --uuid <rule-uuid>'. Replace with narrow " +
		"droplet/tag/cluster references.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.5"},
	},
	Tags:    []string{"database", "network-exposure", "catastrophic"},
	Scanner: "databases.FirewallNoPublicCIDR",
}

func DBFirewallNoPublicCIDR(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		f := compliancekit.Finding{
			CheckID:  CheckDBFirewallNoPublicCIDR.ID,
			Severity: CheckDBFirewallNoPublicCIDR.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBFirewallNoPublicCIDR.Tags,
		}
		offender := ""
		for _, r := range firewallRulesOf(d) {
			t := asString(r["type"])
			v := asString(r["value"])
			if t == "ip_addr" && publicCIDRs[v] {
				offender = v
				break
			}
		}
		if offender != "" {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: trusted source includes %s", d.Name, offender)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: no public CIDR in trusted sources", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBTLSEnabled requires the public connection's SSL flag be
// true. DO managed DBs do support SSL but the flag determines
// whether unencrypted connections are accepted on the public
// endpoint.
var CheckDBTLSEnabled = compliancekit.Check{
	ID:           "do-db-tls-disabled",
	Title:        "Managed databases must require TLS on public endpoints",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "The connection.ssl flag toggles whether the public " +
		"endpoint accepts unencrypted connections. With ssl=false, a " +
		"DB user's password is sent in plaintext over the wire on " +
		"every connection -- catastrophic for any DB reachable from " +
		"anywhere other than localhost.",
	Remediation: "DO managed DBs ship with TLS support but the per-DB " +
		"override on this flag can disable it. Verify in the DO " +
		"control panel under Settings > Connection Details; require " +
		"SSL for all users.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"database", "encryption-in-transit", "tls"},
	Scanner: "databases.TLSEnabled",
}

func DBTLSEnabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		ssl, _ := d.Attributes["public_ssl"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckDBTLSEnabled.ID,
			Severity: CheckDBTLSEnabled.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBTLSEnabled.Tags,
		}
		if ssl {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: SSL enabled on public endpoint", d.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: SSL DISABLED on public endpoint", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBInVPC requires the DB sit in a VPC. Modern DO DBs do by
// default; legacy DBs may not.
var CheckDBInVPC = compliancekit.Check{
	ID:           "do-db-no-vpc",
	Title:        "Managed databases must belong to a VPC",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "A managed DB without a VPC sits on the legacy " +
		"region-wide private network shared by every droplet -- the " +
		"private endpoint isn't private anymore. Recreating in a VPC " +
		"restores the segmentation guarantee.",
	Remediation: "Recreate the DB inside a named VPC. DO does not " +
		"support changing the VPC after creation; the migration is " +
		"app-downtime + restore-from-backup. Schedule accordingly.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2"},
	},
	Tags:    []string{"database", "network", "segmentation"},
	Scanner: "databases.InVPC",
}

func DBInVPC(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		vpc, _ := d.Attributes["vpc_uuid"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckDBInVPC.ID,
			Severity: CheckDBInVPC.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBInVPC.Tags,
		}
		if vpc != "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: in VPC %s", d.Name, vpc)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: no VPC association", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBEngineNotEOL flags engine versions known to be EOL.
var CheckDBEngineNotEOL = compliancekit.Check{
	ID:           "do-db-engine-eol",
	Title:        "Managed databases should not run EOL engine versions",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "DO accepts older engine versions at create time but " +
		"once an engine version is upstream-EOL, security patches " +
		"stop. Examples: Postgres 13 is EOL Nov 2025; MySQL 5.7 is " +
		"EOL Oct 2023. Running these means the DB is missing fixes " +
		"that will never ship.",
	Remediation: "Upgrade in place: 'doctl databases upgrade-major " +
		"<db-id> --version <new>'. Always take a backup first. Plan " +
		"for application-side compatibility testing.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"2.2", "7.4"},
	},
	Tags:    []string{"database", "patching", "eol"},
	Scanner: "databases.EngineNotEOL",
}

func DBEngineNotEOL(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		engine, _ := d.Attributes["engine"].(string)
		version, _ := d.Attributes["version"].(string)
		key := strings.ToLower(engine + ":" + version)
		// Also try matching just the major version prefix.
		majorKey := strings.ToLower(engine + ":" + strings.SplitN(version, ".", 2)[0])

		f := compliancekit.Finding{
			CheckID:  CheckDBEngineNotEOL.ID,
			Severity: CheckDBEngineNotEOL.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBEngineNotEOL.Tags,
		}
		if eolEngineVersions[key] || eolEngineVersions[majorKey] {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: engine %s %s is EOL", d.Name, engine, version)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: engine %s %s", d.Name, engine, version)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBMaintenanceWindow requires a maintenance window be
// configured. Without one DO picks one for you, possibly during
// peak hours.
var CheckDBMaintenanceWindow = compliancekit.Check{
	ID:           "do-db-no-maintenance-window",
	Title:        "Managed databases should have a configured maintenance window",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "Without an explicit maintenance window, DO chooses one " +
		"based on the DB's region default. If the default lands during " +
		"your business hours, scheduled patches cause unexpected " +
		"outages. Set an explicit off-hours window.",
	Remediation: "'doctl databases maintenance-window update <db-id> " +
		"--day sunday --hour 02:00'. Pick a low-traffic window for " +
		"your application.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.5"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.3"},
	},
	Tags:    []string{"database", "patching", "operations"},
	Scanner: "databases.MaintenanceWindow",
}

func DBMaintenanceWindow(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		day, _ := d.Attributes["maintenance_day"].(string)
		hour, _ := d.Attributes["maintenance_hour"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckDBMaintenanceWindow.ID,
			Severity: CheckDBMaintenanceWindow.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBMaintenanceWindow.Tags,
		}
		if day != "" && hour != "" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: maintenance %s %s", d.Name, day, hour)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: no maintenance window configured", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBMultiNode requires production DBs run with more than one
// node (replicas). A single-node managed DB has no HA story.
var CheckDBMultiNode = compliancekit.Check{
	ID:           "do-db-single-node",
	Title:        "Production databases should run with replicas",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "A single-node managed DB has no HA story: any host- " +
		"or zone-level failure takes the DB offline until DO " +
		"reschedules. Multi-node clusters (DO supports up to 3-node " +
		"high-availability) survive single-host failure transparently. " +
		"Skip for dev/staging.",
	Remediation: "Scale up: 'doctl databases resize <db-id> --num-nodes " +
		"2' (or 3 for high-availability clusters). Plan a brief " +
		"maintenance window; DO promotes a standby and the failover " +
		"is fast but not instant.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC7.5"},
		"iso27001": {"A.8.13", "A.8.14"},
		"cis-v8":   {"11.3"},
	},
	Tags:    []string{"database", "availability"},
	Scanner: "databases.MultiNode",
}

func DBMultiNode(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		nodes, _ := d.Attributes["num_nodes"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckDBMultiNode.ID,
			Severity: CheckDBMultiNode.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBMultiNode.Tags,
		}
		if nodes >= 2 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: %d nodes", d.Name, nodes)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: single-node (no HA)", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckDBOnlyDOTrustedSources flags DBs whose trusted-sources
// list contains ip_addr entries (vs droplet / k8s / tag refs).
// Using IP allowlists for managed DBs is brittle -- droplet IPs
// can change; named references are stable.
var CheckDBOnlyDOTrustedSources = compliancekit.Check{
	ID:           "do-db-ip-only-trust",
	Title:        "Managed databases should trust named resources, not raw IPs",
	Severity:     compliancekit.SeverityLow,
	Provider:     "digitalocean",
	Service:      "databases",
	ResourceType: docol.DatabaseType,
	Description: "Trusted-source rules of type ip_addr break silently " +
		"when droplets are recreated and get new IPs. Named " +
		"references (droplet:<id>, tag:<name>, k8s:<cluster-id>) " +
		"survive recreation; IPs need manual update on every " +
		"droplet rotation. Mixing both is fine; relying only on IPs " +
		"is fragile.",
	Remediation: "Convert ip_addr rules to droplet/tag refs: " +
		"'doctl databases firewalls append <db-id> --rule " +
		"droplet:<id>'. Remove the corresponding ip_addr rule.",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.30", "A.8.31"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"database", "operations"},
	Scanner: "databases.NamedTrustedSources",
}

func DBOnlyDOTrustedSources(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, d := range g.ByType(docol.DatabaseType) {
		rules := firewallRulesOf(d)
		if len(rules) == 0 {
			continue // covered by HasFirewallRules check
		}
		ipOnly := true
		for _, r := range rules {
			if asString(r["type"]) != "ip_addr" {
				ipOnly = false
				break
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckDBOnlyDOTrustedSources.ID,
			Severity: CheckDBOnlyDOTrustedSources.Severity,
			Resource: d.Ref(),
			Tags:     CheckDBOnlyDOTrustedSources.Tags,
		}
		if ipOnly {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("db %q: trusted sources are IP-only (use droplet/tag/k8s refs)", d.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("db %q: uses named trusted sources", d.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckDBHasFirewallRules, DBHasFirewallRules)
	compliancekit.Register(CheckDBFirewallNoPublicCIDR, DBFirewallNoPublicCIDR)
	compliancekit.Register(CheckDBTLSEnabled, DBTLSEnabled)
	compliancekit.Register(CheckDBInVPC, DBInVPC)
	compliancekit.Register(CheckDBEngineNotEOL, DBEngineNotEOL)
	compliancekit.Register(CheckDBMaintenanceWindow, DBMaintenanceWindow)
	compliancekit.Register(CheckDBMultiNode, DBMultiNode)
	compliancekit.Register(CheckDBOnlyDOTrustedSources, DBOnlyDOTrustedSources)
}
