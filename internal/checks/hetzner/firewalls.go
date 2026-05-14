package hetzner

import (
	"context"
	"fmt"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

// publicCIDRs are the IPv4 + IPv6 "any source" addresses that
// make an inbound rule effectively world-open.
var publicCIDRs = map[string]bool{
	"0.0.0.0/0": true,
	"::/0":      true,
}

// rulesOf reads the firewall rules slice from a firewall resource.
// Returns an empty slice when missing or wrong type.
func rulesOf(fw core.Resource) []map[string]any {
	r, _ := fw.Attributes["rules"].([]map[string]any)
	return r
}

// CheckFirewallSSHFromAny flags firewalls allowing TCP 22 inbound
// from the public Internet. SOC 2 CC6.6 / ISO 27001 A.8.21 / CIS
// Controls v8 4.4 all require narrow administrative access.
var CheckFirewallSSHFromAny = core.Check{
	ID:           "hetzner-firewall-ssh-from-any",
	Title:        "Hetzner firewalls must not allow SSH (port 22) from the public internet",
	Severity:     core.SeverityHigh,
	Provider:     "hetzner",
	Service:      "firewalls",
	ResourceType: hetznercol.FirewallType,
	Description: "An inbound rule allowing TCP 22 from 0.0.0.0/0 or " +
		"::/0 exposes SSH brute-force attempts to every host on the " +
		"internet. Restrict to bastion IPs, VPN ranges, or use the " +
		"Hetzner Cloud Console SSH gateway.",
	Remediation: "Replace the rule with a narrow source: 'hcloud " +
		"firewall replace-rules <name> --rules-file rules.json' " +
		"with sources scoped to your operator CIDRs.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"firewall", "ssh", "exposure"},
	Scanner: "firewalls.SSHFromAny",
}

func FirewallSSHFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(hetznercol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallSSHFromAny.ID,
			Severity: CheckFirewallSSHFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallSSHFromAny.Tags,
		}
		offender := findRulePublic(rulesOf(fw), "in", "tcp", "22")
		if offender != "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: TCP 22 from %s", fw.Name, offender)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: no public SSH rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckFirewallAnyFromAny flags inbound rules allowing any port
// (Port == "" in our normalization, i.e. no port restriction)
// from the public Internet for protocol tcp/udp. The catastrophic
// "default-allow" shape.
var CheckFirewallAnyFromAny = core.Check{
	ID:           "hetzner-firewall-any-port-from-any",
	Title:        "Hetzner firewalls must not allow any-port from the public internet",
	Severity:     core.SeverityCritical,
	Provider:     "hetzner",
	Service:      "firewalls",
	ResourceType: hetznercol.FirewallType,
	Description: "Hetzner firewall rules can omit the port to mean " +
		"'all ports.' An inbound rule with sources 0.0.0.0/0 and " +
		"no port (or `1-65535`) for TCP/UDP effectively disables " +
		"the firewall. Common shape of pasted-in incident-triage " +
		"rules that survive past the incident.",
	Remediation: "Replace the rule with explicit port lists. " +
		"'hcloud firewall replace-rules <name>' with a narrowly " +
		"scoped rules.json. Audit history if available.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.5"},
	},
	Tags:    []string{"firewall", "exposure", "catastrophic"},
	Scanner: "firewalls.AnyFromAny",
}

func FirewallAnyFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(hetznercol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallAnyFromAny.ID,
			Severity: CheckFirewallAnyFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallAnyFromAny.Tags,
		}
		offending := ""
		for _, r := range rulesOf(fw) {
			if asString(r["direction"]) != "in" {
				continue
			}
			proto := asString(r["protocol"])
			if proto != "tcp" && proto != "udp" {
				continue
			}
			port := asString(r["port"])
			if port != "" && port != "1-65535" && port != "0-65535" {
				continue
			}
			srcs, _ := r["source_ips"].([]string)
			for _, s := range srcs {
				if publicCIDRs[s] {
					offending = fmt.Sprintf("%s any-port from %s", proto, s)
					break
				}
			}
			if offending != "" {
				break
			}
		}
		if offending != "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: %s", fw.Name, offending)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: no any-port-from-any rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckFirewallOrphan flags firewalls applied to zero resources.
// They protect nothing and pollute the audit trail.
var CheckFirewallOrphan = core.Check{
	ID:           "hetzner-firewall-orphan",
	Title:        "Hetzner firewalls should be applied to at least one resource",
	Severity:     core.SeverityLow,
	Provider:     "hetzner",
	Service:      "firewalls",
	ResourceType: hetznercol.FirewallType,
	Description: "A firewall with zero AppliedTo entries protects " +
		"nothing. They accumulate as servers are deleted but the " +
		"firewalls are left behind. Cleaning them up makes 'which " +
		"firewall protects this server?' answerable in one query.",
	Remediation: "Either apply the firewall to a server or label " +
		"selector ('hcloud firewall apply-to-resource ...') or " +
		"delete it ('hcloud firewall delete <name>').",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"firewall", "hygiene"},
	Scanner: "firewalls.Orphan",
}

func FirewallOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(hetznercol.FirewallType) {
		count, _ := fw.Attributes["applied_count"].(int)
		f := core.Finding{
			CheckID:  CheckFirewallOrphan.ID,
			Severity: CheckFirewallOrphan.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallOrphan.Tags,
		}
		if count > 0 {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: applied to %d resource(s)", fw.Name, count)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: applied to nothing", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// findRulePublic returns the offending source CIDR if any rule
// matches (direction, protocol, port) and has a public source.
func findRulePublic(rules []map[string]any, direction, protocol, port string) string {
	for _, r := range rules {
		if asString(r["direction"]) != direction {
			continue
		}
		if asString(r["protocol"]) != protocol {
			continue
		}
		if asString(r["port"]) != port {
			continue
		}
		srcs, _ := r["source_ips"].([]string)
		for _, s := range srcs {
			if publicCIDRs[s] {
				return s
			}
		}
	}
	return ""
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func init() {
	core.Register(CheckFirewallSSHFromAny, FirewallSSHFromAny)
	core.Register(CheckFirewallAnyFromAny, FirewallAnyFromAny)
	core.Register(CheckFirewallOrphan, FirewallOrphan)
}
