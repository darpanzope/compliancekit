package linux

import (
	"context"
	"fmt"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// firewallOf returns the firewall sub-map on a host Resource, or
// (nil, false) when unavailable.
func firewallOf(host compliancekit.Resource) (map[string]any, bool) {
	if !host.AttrBool("reachable") {
		return nil, false
	}
	raw, ok := host.Attributes["firewall"]
	if !ok {
		return nil, false
	}
	fw, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	return fw, true
}

// firewallSkip is the shared StatusSkip builder for the firewall checks.
func firewallSkip(check compliancekit.Check, host compliancekit.Resource) compliancekit.Finding {
	return compliancekit.Finding{
		CheckID:  check.ID,
		Severity: check.Severity,
		Status:   compliancekit.StatusSkip,
		Resource: host.Ref(),
		Message:  "firewall state unavailable",
		Tags:     check.Tags,
	}
}

// ============================================================
// linux-firewall-active
// ============================================================

// CheckFirewallActive requires ufw or nftables to be active.
var CheckFirewallActive = compliancekit.Check{
	ID:           "linux-firewall-active",
	Title:        "A host firewall must be active",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "linux",
	Service:      "firewall",
	ResourceType: linuxcol.HostType,
	Description: "A host with no active firewall accepts every packet " +
		"its NIC sees. ufw and nftables are the two modern Linux " +
		"options; this check passes when either reports an active " +
		"state. SOC 2 CC6.6, ISO 27001 A.8.20, and CIS Controls v8 " +
		"4.4 all require network access controls on production hosts.",
	Remediation: "Enable ufw ('sudo ufw enable' on Debian/Ubuntu) or " +
		"nftables ('sudo systemctl enable --now nftables'). Verify " +
		"with 'sudo ufw status' or 'sudo nft list ruleset'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"firewall", "network"},
	Scanner: "firewall.Active",
}

// FirewallActive is the CheckFunc for CheckFirewallActive.
func FirewallActive(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]compliancekit.Finding, 0, len(hosts))
	for _, h := range hosts {
		fw, ok := firewallOf(h)
		if !ok {
			findings = append(findings, firewallSkip(CheckFirewallActive, h))
			continue
		}
		ufw, _ := fw["ufw_active"].(bool)
		nft, _ := fw["nftables_active"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckFirewallActive.ID,
			Severity: CheckFirewallActive.Severity,
			Resource: h.Ref(),
			Tags:     CheckFirewallActive.Tags,
		}
		switch {
		case ufw && nft:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: ufw and nftables both active", h.Name)
		case ufw:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: ufw active", h.Name)
		case nft:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("host %q: nftables active", h.Name)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("host %q: neither ufw nor nftables is active", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ============================================================
// linux-firewall-default-deny
// ============================================================

// CheckFirewallDefaultDeny requires ufw's default-incoming policy to
// be "deny". This is a ufw-specific check; nftables-only hosts are
// Skipped because the equivalent assertion requires parsing nft rules.
var CheckFirewallDefaultDeny = compliancekit.Check{
	ID:           "linux-firewall-default-deny",
	Title:        "Firewall default-incoming policy must be deny",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "linux",
	Service:      "firewall",
	ResourceType: linuxcol.HostType,
	Description: "An active firewall whose default policy is allow is " +
		"only slightly safer than no firewall at all -- every port " +
		"without an explicit deny rule is reachable. Default-deny " +
		"with explicit allows is the only defensible posture. SOC 2 " +
		"CC6.6, ISO 27001 A.8.20, and CIS Controls v8 4.4 require this.",
	Remediation: "On ufw: 'sudo ufw default deny incoming'. On nftables, " +
		"set the inet filter input chain policy to drop.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"firewall", "network", "default-policy"},
	Scanner: "firewall.DefaultDeny",
}

// FirewallDefaultDeny is the CheckFunc for CheckFirewallDefaultDeny.
//
// Behavior:
//   - host unreachable / firewall probe failed -> Skip
//   - ufw active and default_incoming == "deny" -> Pass
//   - ufw active and default_incoming == anything else -> Fail
//   - nftables active but no ufw -> Skip (we don't parse nft rules yet)
//   - neither active -> Fail (covered better by FirewallActive, but
//     this check also fires for completeness)
func FirewallDefaultDeny(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	hosts := g.ByType(linuxcol.HostType)
	findings := make([]compliancekit.Finding, 0, len(hosts))
	for _, h := range hosts {
		fw, ok := firewallOf(h)
		if !ok {
			findings = append(findings, firewallSkip(CheckFirewallDefaultDeny, h))
			continue
		}
		ufw, _ := fw["ufw_active"].(bool)
		nft, _ := fw["nftables_active"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckFirewallDefaultDeny.ID,
			Severity: CheckFirewallDefaultDeny.Severity,
			Resource: h.Ref(),
			Tags:     CheckFirewallDefaultDeny.Tags,
		}
		switch {
		case ufw:
			policy, _ := fw["ufw_default_incoming"].(string)
			if policy == "deny" {
				f.Status = compliancekit.StatusPass
				f.Message = fmt.Sprintf("host %q: ufw default-incoming=deny", h.Name)
			} else {
				f.Status = compliancekit.StatusFail
				f.Message = fmt.Sprintf("host %q: ufw default-incoming=%q (want deny)", h.Name, policy)
			}
		case nft:
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("host %q: nftables active; nft policy parsing lands later", h.Name)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("host %q: no active firewall to enforce a default policy", h.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckFirewallActive, FirewallActive)
	compliancekit.Register(CheckFirewallDefaultDeny, FirewallDefaultDeny)
}
