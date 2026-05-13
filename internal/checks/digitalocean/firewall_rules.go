package digitalocean

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// sshPort is the well-known SSH port. Tracking it as a const keeps the
// check readable.
const sshPort = "22"

// publicCIDRs are the IPv4 + IPv6 "any source" addresses that make an
// inbound rule effectively world-open.
var publicCIDRs = map[string]bool{
	"0.0.0.0/0": true,
	"::/0":      true,
}

// CheckSSHFromAny flags firewall inbound rules that allow SSH (port 22)
// from 0.0.0.0/0 or ::/0 -- effectively allowing brute-force attempts
// from anywhere on the internet.
var CheckSSHFromAny = core.Check{
	ID:           "do-firewall-ssh-from-any",
	Title:        "Firewalls must not allow SSH (port 22) from the public internet",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "An inbound firewall rule allowing TCP port 22 from " +
		"0.0.0.0/0 or ::/0 exposes SSH brute-force attempts to every " +
		"host on the internet. Restrict SSH to bastion IPs, VPN " +
		"ranges, or use the DigitalOcean web console SSH gateway. " +
		"SOC 2 CC6.6, ISO 27001 A.8.21, and CIS Controls v8 4.4 all " +
		"require restricted administrative access.",
	Remediation: "Replace the rule with a narrow source range: " +
		"'doctl compute firewall update <id> " +
		"--inbound-rules \"protocol:tcp,ports:22,sources:address:" +
		"203.0.113.0/24\"'. In Terraform, narrow the 'sources.addresses' " +
		"list on the matching inbound_rule block.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"network", "ssh", "exposure"},
	Scanner: "firewalls.SSHFromAny",
}

// SSHFromAny is the CheckFunc for CheckSSHFromAny. Iterates every
// firewall and inspects its inbound_rules for port 22 + a "0.0.0.0/0"
// or "::/0" source. A firewall with no SSH rule at all is Pass (the
// rule isn't there to be too permissive).
func SSHFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	firewalls := g.ByType(docol.FirewallType)
	findings := make([]core.Finding, 0, len(firewalls))

	for _, fw := range firewalls {
		f := core.Finding{
			CheckID:  CheckSSHFromAny.ID,
			Severity: CheckSSHFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckSSHFromAny.Tags,
		}

		rules, ok := fw.Attributes["inbound_rules"].([]godo.InboundRule)
		if !ok {
			f.Status = core.StatusSkip
			f.Message = "firewall has no inbound_rules attribute"
			findings = append(findings, f)
			continue
		}

		if exposed := findSSHFromAny(rules); exposed != "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf(
				"firewall %q allows SSH from %s (effectively the public internet)",
				fw.Name, exposed)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q has no public SSH rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// findSSHFromAny returns the offending CIDR string if any inbound rule
// allows TCP port 22 from a public-internet source, or "" otherwise.
func findSSHFromAny(rules []godo.InboundRule) string {
	for _, r := range rules {
		if r.Protocol != "tcp" {
			continue
		}
		if !rulePortIncludes(r.PortRange, sshPort) {
			continue
		}
		if r.Sources == nil {
			continue
		}
		for _, addr := range r.Sources.Addresses {
			if publicCIDRs[addr] {
				return addr
			}
		}
	}
	return ""
}

// rulePortIncludes reports whether portRange covers a single port string.
// DO API accepts "22", "22-25", or "all"; we treat "all" as "yes" and
// otherwise look for an exact match. Single-port checks for v0.1 don't
// need to parse "22-25" -- that lands when we add a generic "port-X-
// from-any" family of checks.
func rulePortIncludes(portRange, port string) bool {
	return portRange == port || portRange == "all"
}

func init() {
	core.Register(CheckSSHFromAny.ID, SSHFromAny)
}
