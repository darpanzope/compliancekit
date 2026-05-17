package linux

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.20 phase 8 — firewall depth. Three real-data checks against the
// existing ufw/nftables collector + seven manual-verify checks for
// the dimensions firewall semantics make impractical to validate
// statically (per-rule logging cadence, rate-limit thresholds, IPv6
// parity).

// ----- real-data --------------------------------------------------------

var CheckFirewallUFWDefaultDenyOutgoing = core.Check{
	ID:           "linux-firewall-ufw-default-deny-outgoing",
	Title:        "ufw default policy: outgoing must be deny on egress-controlled hosts",
	Severity:     core.SeverityMedium,
	Provider:     "linux",
	Service:      "firewall",
	ResourceType: docol.HostType,
	Description: "Default-deny egress is the modern way to constrain a compromised process " +
		"from beacons / data-exfil. CIS Linux Server v8 §3.4.2.1 recommends explicit " +
		"egress allow-lists with default deny. Waive on hosts that need broad outbound " +
		"access (build runners, package mirrors).",
	Remediation: "sudo ufw default deny outgoing\n" +
		"sudo ufw allow out 443/tcp comment 'HTTPS'\n" +
		"sudo ufw allow out 53      comment 'DNS'\n" +
		"sudo ufw reload",
	Frameworks: map[string][]string{
		"soc2":             {"CC6.6"},
		"iso27001":         {"A.8.20"},
		"cis-v8":           {"3.4.2.1"},
		"cis-linux-server": {"3.4.2.1"},
	},
	Tags:    []string{"firewall", "ufw", "egress"},
	Scanner: "linux.firewall.UFWDefaultDenyOutgoing",
}

func FirewallUFWDefaultDenyOutgoing(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := core.Finding{
			CheckID:  CheckFirewallUFWDefaultDenyOutgoing.ID,
			Severity: CheckFirewallUFWDefaultDenyOutgoing.Severity,
			Resource: h.Ref(),
			Tags:     CheckFirewallUFWDefaultDenyOutgoing.Tags,
		}
		fw, _ := h.Attributes["firewall"].(map[string]any)
		if fw == nil {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: firewall attribute missing", h.Name)
			findings = append(findings, f)
			continue
		}
		active, _ := fw["ufw_active"].(bool)
		if !active {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("host %q: ufw not active; check skipped (other firewall, or no firewall)", h.Name)
			findings = append(findings, f)
			continue
		}
		out, _ := fw["ufw_default_outgoing"].(string)
		if out == "deny" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: ufw default outgoing=deny", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: ufw default outgoing=%q (must be deny on egress-controlled hosts)", h.Name, out)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckFirewallSomeActive = core.Check{
	ID:           "linux-firewall-some-active",
	Title:        "Some firewall must be active (ufw, nftables, or firewalld)",
	Severity:     core.SeverityHigh,
	Provider:     "linux",
	Service:      "firewall",
	ResourceType: docol.HostType,
	Description: "A host with NO active firewall trusts the upstream cloud provider's " +
		"security groups entirely. Defense in depth wants both — at minimum a nftables " +
		"default-deny INPUT table on RHEL-family or ufw active on Debian-family.",
	Remediation: "Debian/Ubuntu: sudo ufw enable\nRHEL family: sudo systemctl enable --now nftables firewalld",
	Frameworks: map[string][]string{
		"soc2":             {"CC6.6"},
		"iso27001":         {"A.8.20"},
		"cis-v8":           {"3.4.1"},
		"cis-linux-server": {"3.4.1"},
	},
	Tags:    []string{"firewall", "must-active"},
	Scanner: "linux.firewall.SomeActive",
}

func FirewallSomeActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := core.Finding{
			CheckID:  CheckFirewallSomeActive.ID,
			Severity: CheckFirewallSomeActive.Severity,
			Resource: h.Ref(),
			Tags:     CheckFirewallSomeActive.Tags,
		}
		fw, _ := h.Attributes["firewall"].(map[string]any)
		if fw == nil {
			f.Status = core.StatusError
			f.Message = fmt.Sprintf("host %q: firewall attribute missing", h.Name)
			findings = append(findings, f)
			continue
		}
		ufw, _ := fw["ufw_active"].(bool)
		nft, _ := fw["nftables_active"].(bool)
		if ufw || nft {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: firewall active (ufw=%v nftables=%v)", h.Name, ufw, nft)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: no firewall service active", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckFirewallNFTablesOnRHEL = core.Check{
	ID:           "linux-firewall-nftables-on-rhel",
	Title:        "RHEL-family hosts should run nftables (modern replacement for iptables)",
	Severity:     core.SeverityLow,
	Provider:     "linux",
	Service:      "firewall",
	ResourceType: docol.HostType,
	Description: "nftables is the upstream replacement for iptables; RHEL 8+ ships with " +
		"firewalld backed by nftables. Hosts in the RHEL family running iptables-only " +
		"miss the cleaner rule grammar + atomic rule replacement. Debian/Ubuntu still " +
		"defaults to ufw — this check skips there.",
	Remediation: "sudo systemctl enable --now nftables\nMigrate iptables rules via `iptables-restore-translate -f /etc/sysconfig/iptables`.",
	Frameworks: map[string][]string{
		"soc2":             {"CC6.6"},
		"iso27001":         {"A.8.20"},
		"cis-v8":           {"3.4.2"},
		"cis-linux-server": {"3.4.2"},
	},
	Tags:    []string{"firewall", "nftables", "rhel"},
	Scanner: "linux.firewall.NFTablesOnRHEL",
}

func FirewallNFTablesOnRHEL(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, h := range g.ByType(docol.HostType) {
		f := core.Finding{
			CheckID:  CheckFirewallNFTablesOnRHEL.ID,
			Severity: CheckFirewallNFTablesOnRHEL.Severity,
			Resource: h.Ref(),
			Tags:     CheckFirewallNFTablesOnRHEL.Tags,
		}
		// Only flag on RHEL family.
		rel, _ := h.Attributes["os_release"].(docol.OSRelease)
		if !rel.IsRHELFamily() {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("host %q: not RHEL family (id=%s); nftables-on-RHEL check N/A", h.Name, rel.ID)
			findings = append(findings, f)
			continue
		}
		fw, _ := h.Attributes["firewall"].(map[string]any)
		nft, _ := fw["nftables_active"].(bool)
		if nft {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("host %q: nftables active", h.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("host %q: RHEL family host without nftables active", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- manual-verify (7) ------------------------------------------------

var manualFirewallChecks = []manualVerifySpec{
	{id: "linux-firewall-loopback-allowed", title: "Firewall must allow loopback traffic",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.4"},
		tags:       []string{"firewall", "loopback", "manual-verify"},
		descSuffix: "Localhost / 127.0.0.0/8 / ::1 traffic must be allowed. Most distros include this rule by default; explicit-deny INPUT policies sometimes drop it.",
		hint:       "`sudo iptables -L INPUT | grep -i lo` OR `sudo nft list ruleset | grep iif lo`",
		scanner:    "linux.firewall.LoopbackAllowed"},
	{id: "linux-firewall-icmp-input-restricted", title: "ICMP INPUT must be rate-limited",
		severity: core.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.5"},
		tags:       []string{"firewall", "icmp", "manual-verify"},
		descSuffix: "Unbounded ICMP echo replies are a ping-flood amplifier. Limit to ≤5/sec.",
		hint:       "`sudo iptables -L INPUT | grep -i icmp` OR `sudo nft list ruleset | grep icmp`",
		scanner:    "linux.firewall.ICMPRestricted"},
	{id: "linux-firewall-ipv6-rules-present", title: "IPv6 firewall rules must mirror IPv4",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.7"},
		tags:       []string{"firewall", "ipv6", "manual-verify"},
		descSuffix: "An IPv4-only firewall on a dual-stack host leaves the IPv6 stack default-permit. Hosts with IPv6 enabled need ip6tables / inet6 rules to mirror IPv4.",
		hint:       "`sudo ip6tables -L | head` OR `sudo nft list ruleset | grep ip6`",
		scanner:    "linux.firewall.IPv6Rules"},
	{id: "linux-firewall-egress-policy-documented", title: "Egress allow-list must be documented",
		severity: core.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.6"},
		tags:       []string{"firewall", "egress", "manual-verify"},
		descSuffix: "Default-deny egress requires a documented allow-list (which fqdns + ports + protocols are intentional). Without that list, every new outbound flow that fails is a guess.",
		hint:       "Document the allow-list in your runbook; the firewall rules should match.",
		scanner:    "linux.firewall.EgressDocumented"},
	{id: "linux-firewall-rules-logged", title: "Firewall drops should be logged",
		severity: core.SeverityLow, soc2: []string{"CC7.2"}, iso: []string{"A.8.15"}, cis: []string{"3.4.2.8"},
		tags:       []string{"firewall", "logging", "manual-verify"},
		descSuffix: "Logged drops feed the SIEM with reconnaissance / scan signals. Most distros disable LOG by default to keep dmesg quiet.",
		hint:       "`sudo iptables -L | grep LOG` OR `sudo nft list ruleset | grep log`",
		scanner:    "linux.firewall.RulesLogged"},
	{id: "linux-firewall-ssh-rate-limited", title: "SSH ingress must be rate-limited",
		severity: core.SeverityMedium, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.9"},
		tags:       []string{"firewall", "ssh", "manual-verify"},
		descSuffix: "Rate-limiting SSH (e.g. ufw limit 22) blocks credential-stuffing without changing the auth posture.",
		hint:       "`sudo ufw status verbose | grep -i limit` OR `sudo iptables -L | grep recent`",
		scanner:    "linux.firewall.SSHRateLimited"},
	{id: "linux-firewall-dns-egress-restricted", title: "DNS egress must be restricted to known resolvers",
		severity: core.SeverityLow, soc2: []string{"CC6.6"}, iso: []string{"A.8.20"}, cis: []string{"3.4.2.10"},
		tags:       []string{"firewall", "dns", "manual-verify"},
		descSuffix: "Unrestricted port 53 egress is a common DNS-tunneling exfil channel. Restrict to your resolver IPs.",
		hint:       "`sudo iptables -L OUTPUT | grep 53` + cross-reference /etc/resolv.conf.",
		scanner:    "linux.firewall.DNSEgressRestricted"},
}

func init() {
	core.Register(CheckFirewallUFWDefaultDenyOutgoing, FirewallUFWDefaultDenyOutgoing)
	core.Register(CheckFirewallSomeActive, FirewallSomeActive)
	core.Register(CheckFirewallNFTablesOnRHEL, FirewallNFTablesOnRHEL)
	for _, spec := range manualFirewallChecks {
		spec := spec
		core.Register(manualVerifyCheck(spec), manualVerifyFunc(spec))
	}
}
