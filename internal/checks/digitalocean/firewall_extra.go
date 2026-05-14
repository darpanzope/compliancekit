package digitalocean

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/digitalocean/godo"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

const (
	rdpPort = "3389"

	// broadPortThreshold is the size beyond which we consider an
	// inbound port range "too broad" -- the count of ports a single
	// rule covers if it allows public-internet sources. 1024 is the
	// boundary between privileged + unprivileged ports; a rule that
	// opens more than that almost certainly didn't mean to.
	broadPortThreshold = 1024
)

// inboundRulesOf returns the firewall's inbound rules, or false if
// the attribute is missing or the wrong type.
func inboundRulesOf(fw core.Resource) ([]godo.InboundRule, bool) {
	rules, ok := fw.Attributes["inbound_rules"].([]godo.InboundRule)
	return rules, ok
}

func outboundRulesOf(fw core.Resource) ([]godo.OutboundRule, bool) {
	rules, ok := fw.Attributes["outbound_rules"].([]godo.OutboundRule)
	return rules, ok
}

// CheckFirewallRDPFromAny is the RDP-equivalent of SSHFromAny. Port
// 3389 from the public internet is a much higher exploit-velocity
// surface than SSH (most droplets are Linux, but the rare Windows
// droplet behind a wide-open RDP rule is a magnet for
// credential-stuffing).
var CheckFirewallRDPFromAny = core.Check{
	ID:           "do-firewall-rdp-from-any",
	Title:        "Firewalls must not allow RDP (port 3389) from the public internet",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "Public-Internet RDP exposure on port 3389 is the single " +
		"highest-velocity ransomware entry vector in the field. Even " +
		"with rate-limiting, valid-credential discovery by botnet is " +
		"measured in days. Restrict RDP to bastion / jump-host IPs or " +
		"a managed VPN range; never expose it to 0.0.0.0/0 / ::/0.",
	Remediation: "Narrow the source list: 'doctl compute firewall update " +
		"<id> --inbound-rules \"protocol:tcp,ports:3389,sources:" +
		"address:203.0.113.0/24\"'. Better: put Windows hosts behind a " +
		"VPN concentrator and remove the 3389 rule entirely.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"network", "rdp", "exposure"},
	Scanner: "firewalls.RDPFromAny",
}

func FirewallRDPFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallRDPFromAny.ID,
			Severity: CheckFirewallRDPFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallRDPFromAny.Tags,
		}
		rules, ok := inboundRulesOf(fw)
		if !ok {
			f.Status = core.StatusSkip
			f.Message = "firewall has no inbound_rules attribute"
			findings = append(findings, f)
			continue
		}
		if exposed := findPortFromAny(rules, "tcp", rdpPort); exposed != "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q allows RDP from %s", fw.Name, exposed)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q has no public RDP rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckFirewallAnyFromAny flags rules that open ALL ports from the
// public Internet. This is the catastrophic "default-allow" rule
// shape -- a single mistake on a firewall update sets the entire
// allowlist to 0.0.0.0/0:any.
var CheckFirewallAnyFromAny = core.Check{
	ID:           "do-firewall-any-port-from-any",
	Title:        "Firewalls must not allow any-port from the public internet",
	Severity:     core.SeverityCritical,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "A firewall rule with sources 0.0.0.0/0 (or ::/0) AND " +
		"portRange of 'all' or every-port effectively disables the " +
		"firewall. This is the catastrophic shape of an accidental " +
		"'allow everything' rule -- usually pasted in during incident " +
		"triage and never reverted. CIS Controls v8 4.5 prescribes " +
		"explicit deny baselines with narrowly-scoped allow rules.",
	Remediation: "Open the firewall and remove or scope down any rule " +
		"with 'ports: all' from a public source. Replace with the " +
		"specific ports + sources actually needed. Audit by source: " +
		"'doctl compute firewall get <id> --format Name,Inbound,Outbound'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.5", "12.2"},
	},
	Tags:    []string{"network", "exposure", "catastrophic"},
	Scanner: "firewalls.AnyFromAny",
}

func FirewallAnyFromAny(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallAnyFromAny.ID,
			Severity: CheckFirewallAnyFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallAnyFromAny.Tags,
		}
		rules, ok := inboundRulesOf(fw)
		if !ok {
			f.Status = core.StatusSkip
			f.Message = "firewall has no inbound_rules attribute"
			findings = append(findings, f)
			continue
		}
		offending := ""
		for _, r := range rules {
			if r.PortRange != "all" && r.PortRange != "0" {
				continue
			}
			if r.Sources == nil {
				continue
			}
			for _, addr := range r.Sources.Addresses {
				if publicCIDRs[addr] {
					offending = fmt.Sprintf("%s/%s from %s", r.Protocol, r.PortRange, addr)
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
			f.Message = fmt.Sprintf("firewall %q: no public any-port rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckFirewallBroadPortRange flags inbound rules from public CIDRs
// where the port range covers more than broadPortThreshold ports.
// Catches the "I just opened 1000-65535 instead of the one port"
// shape.
var CheckFirewallBroadPortRange = core.Check{
	ID:           "do-firewall-broad-port-range",
	Title:        "Firewalls must not open broad port ranges to the public internet",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "An inbound rule from a public source that spans more " +
		"than 1024 ports is almost always a mistake -- the intent was " +
		"a single port (or a small contiguous family) and the typo " +
		"opened the whole unprivileged range. The check fails on any " +
		"public-internet inbound rule whose port count exceeds 1024.",
	Remediation: "Narrow the port range. 'doctl compute firewall update " +
		"<id>' with the actual port(s) you intended. Audit the rule " +
		"history if available; broad ranges in firewall rules tend to " +
		"land via copy/paste error during incident triage.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"network", "exposure", "port-hygiene"},
	Scanner: "firewalls.BroadPortRange",
}

func FirewallBroadPortRange(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallBroadPortRange.ID,
			Severity: CheckFirewallBroadPortRange.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallBroadPortRange.Tags,
		}
		rules, ok := inboundRulesOf(fw)
		if !ok {
			f.Status = core.StatusSkip
			f.Message = "firewall has no inbound_rules attribute"
			findings = append(findings, f)
			continue
		}
		hits := []string{}
		for _, r := range rules {
			n := portRangeSize(r.PortRange)
			if n <= broadPortThreshold {
				continue
			}
			if r.Sources == nil {
				continue
			}
			for _, addr := range r.Sources.Addresses {
				if publicCIDRs[addr] {
					hits = append(hits, fmt.Sprintf("%s/%s from %s (%d ports)", r.Protocol, r.PortRange, addr, n))
					break
				}
			}
		}
		if len(hits) > 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: %d broad public rule(s): %s",
				fw.Name, len(hits), strings.Join(hits, "; "))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: no broad public port ranges", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// portRangeSize returns the count of ports a DO port range string
// covers. "22" = 1, "20-30" = 11, "all" = 65536, anything
// unparsable = 0 (caller treats as not-broad).
func portRangeSize(pr string) int {
	if pr == "all" || pr == "0" {
		return 65536
	}
	if !strings.Contains(pr, "-") {
		if _, err := strconv.Atoi(pr); err != nil {
			return 0
		}
		return 1
	}
	parts := strings.SplitN(pr, "-", 2)
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || hi < lo {
		return 0
	}
	return hi - lo + 1
}

// CheckFirewallOutboundDenyAll flags firewalls with no outbound
// rules. DO treats missing outbound as "allow nothing" so that's
// actually safe -- the check INVERTS: a firewall with a wide-open
// outbound rule (all ports + all protocols to 0.0.0.0/0) is the
// real problem because outbound is how data exfiltration leaves.
var CheckFirewallOutboundDenyAll = core.Check{
	ID:           "do-firewall-outbound-any-to-any",
	Title:        "Firewalls should not allow outbound any-to-any",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "An outbound rule with destinations 0.0.0.0/0 (or ::/0) " +
		"AND portRange 'all' is the egress-allow-everything shape. " +
		"Data exfiltration leaves over outbound; restricting outbound " +
		"to known destinations (Spaces endpoint, GitHub Container " +
		"Registry, NTP, your own DNS resolver) is the standard hardening " +
		"step. This check is informational at v0.9 because most " +
		"droplets legitimately need broad outbound for OS package " +
		"updates -- but the rule should be explicit, not catch-all.",
	Remediation: "Replace the catch-all with explicit destinations + ports. " +
		"At minimum: outbound to your update mirrors, to your " +
		"observability provider, to known internal subnets. Drop the " +
		"0.0.0.0/0 / 'all' combo.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.21", "A.8.22"},
		"cis-v8":   {"13.4", "13.6"},
	},
	Tags:    []string{"network", "egress", "exfiltration"},
	Scanner: "firewalls.OutboundAnyToAny",
}

func FirewallOutboundDenyAll(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallOutboundDenyAll.ID,
			Severity: CheckFirewallOutboundDenyAll.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallOutboundDenyAll.Tags,
		}
		rules, ok := outboundRulesOf(fw)
		if !ok {
			f.Status = core.StatusSkip
			f.Message = "firewall has no outbound_rules attribute"
			findings = append(findings, f)
			continue
		}
		offending := ""
		for _, r := range rules {
			if r.PortRange != "all" && r.PortRange != "0" {
				continue
			}
			if r.Destinations == nil {
				continue
			}
			for _, addr := range r.Destinations.Addresses {
				if publicCIDRs[addr] {
					offending = fmt.Sprintf("%s/%s to %s", r.Protocol, r.PortRange, addr)
					break
				}
			}
			if offending != "" {
				break
			}
		}
		if offending != "" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q outbound: %s", fw.Name, offending)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: no any-to-any outbound rule", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckFirewallOrphan flags firewalls attached to no droplets and
// no tags. Such firewalls do nothing but they clutter the audit
// trail and confuse incident response ("which firewall guards
// what?").
var CheckFirewallOrphan = core.Check{
	ID:           "do-firewall-orphan",
	Title:        "Firewalls should be attached to at least one droplet or tag",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "firewalls",
	ResourceType: docol.FirewallType,
	Description: "A firewall with zero attached droplets and zero matched " +
		"tags protects nothing -- it shows up in the audit trail and " +
		"in incident response readouts but its rules apply to no " +
		"workload. These accumulate as droplets are destroyed and the " +
		"firewall is left behind. Cleaning them up makes 'what " +
		"firewall protects this resource?' answerable in one query.",
	Remediation: "Either attach the firewall to droplets/tags that " +
		"actually need it, or delete it: 'doctl compute firewall " +
		"delete <id>'. Match firewall lifecycle to the tag or droplet " +
		"group it protects.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"network", "hygiene"},
	Scanner: "firewalls.Orphan",
}

func FirewallOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, fw := range g.ByType(docol.FirewallType) {
		f := core.Finding{
			CheckID:  CheckFirewallOrphan.ID,
			Severity: CheckFirewallOrphan.Severity,
			Resource: fw.Ref(),
			Tags:     CheckFirewallOrphan.Tags,
		}
		ids, _ := fw.Attributes["droplet_ids"].([]int)
		tagAttached := len(fw.Tags) > 0
		if len(ids) == 0 && !tagAttached {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("firewall %q: no attached droplets or tags", fw.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("firewall %q: %d droplet(s), %d tag(s)", fw.Name, len(ids), len(fw.Tags))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// findPortFromAny is a generic helper for "protocol+port from public
// internet" checks. Returns the offending CIDR, or "" if no rule
// matches.
func findPortFromAny(rules []godo.InboundRule, protocol, port string) string {
	for _, r := range rules {
		if r.Protocol != protocol {
			continue
		}
		if !rulePortIncludes(r.PortRange, port) {
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

func init() {
	core.Register(CheckFirewallRDPFromAny, FirewallRDPFromAny)
	core.Register(CheckFirewallAnyFromAny, FirewallAnyFromAny)
	core.Register(CheckFirewallBroadPortRange, FirewallBroadPortRange)
	core.Register(CheckFirewallOutboundDenyAll, FirewallOutboundDenyAll)
	core.Register(CheckFirewallOrphan, FirewallOrphan)
}
