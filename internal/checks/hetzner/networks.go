package hetzner

import (
	"context"
	"fmt"
	"strings"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// rfc1918Prefixes are the IPv4 private-range prefixes per
// RFC1918. A network whose IPRange falls outside these is either
// an exotic deliberate setup or a misconfiguration that exposes
// "private" traffic over routable address space.
var rfc1918Prefixes = []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."}

// CheckNetworkOrphan flags private networks with zero attached
// servers and zero attached load balancers. They're dead weight.
var CheckNetworkOrphan = compliancekit.Check{
	ID:           "hetzner-network-orphan",
	Title:        "Hetzner private networks should have at least one member",
	Severity:     compliancekit.SeverityLow,
	Provider:     "hetzner",
	Service:      "networks",
	ResourceType: hetznercol.NetworkType,
	Description: "A private network with zero servers AND zero load " +
		"balancers attached protects nothing. Reserved IP range, " +
		"appears in audit reports, no actual workload uses it. " +
		"Either attach members or delete.",
	Remediation: "List: 'hcloud network list --output columns=name," +
		"ip_range,servers'. For empty networks, either attach servers " +
		"via 'hcloud server attach-to-network' or delete via 'hcloud " +
		"network delete <name>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"network", "hygiene"},
	Scanner: "networks.Orphan",
}

func NetworkOrphan(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(hetznercol.NetworkType) {
		count, _ := n.Attributes["member_count"].(int)
		f := compliancekit.Finding{
			CheckID:  CheckNetworkOrphan.ID,
			Severity: CheckNetworkOrphan.Severity,
			Resource: n.Ref(),
			Tags:     CheckNetworkOrphan.Tags,
		}
		if count > 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("network %q: %d member(s)", n.Name, count)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("network %q: no servers or LBs attached", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNetworkRFC1918 requires the network IPRange fall inside
// an RFC1918 private range. A network using a public IPv4 range
// for its internal traffic surfaces "private" data over IPs that
// can route on the broader internet — almost never intentional.
var CheckNetworkRFC1918 = compliancekit.Check{
	ID:           "hetzner-network-non-rfc1918",
	Title:        "Hetzner private networks should use RFC1918 address space",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "hetzner",
	Service:      "networks",
	ResourceType: hetznercol.NetworkType,
	Description: "Hetzner Cloud private networks can be assigned any " +
		"IPv4 CIDR. RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, " +
		"192.168.0.0/16) are the standard private space and what " +
		"every other tool expects 'private' to mean. A network on " +
		"a public range may route traffic in surprising ways at the " +
		"underlying carrier — defensively keep private networks in " +
		"private space.",
	Remediation: "Hetzner doesn't support changing a network's IP range " +
		"in place. Recreate the network with an RFC1918 CIDR " +
		"('hcloud network create --name <name> --ip-range " +
		"10.20.0.0/16') and reattach members.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.2"},
	},
	Tags:    []string{"network", "addressing"},
	Scanner: "networks.RFC1918",
}

func NetworkRFC1918(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(hetznercol.NetworkType) {
		cidr, _ := n.Attributes["ip_range"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckNetworkRFC1918.ID,
			Severity: CheckNetworkRFC1918.Severity,
			Resource: n.Ref(),
			Tags:     CheckNetworkRFC1918.Tags,
		}
		switch {
		case cidr == "":
			f.Status = compliancekit.StatusSkip
			f.Message = fmt.Sprintf("network %q: no IP range available", n.Name)
		case isRFC1918(cidr):
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("network %q: %s (RFC1918)", n.Name, cidr)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("network %q: %s is outside RFC1918 private space", n.Name, cidr)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// isRFC1918 returns true if the CIDR's address prefix matches any
// RFC1918 private range. Approximate but covers the cases — the
// alternative is parsing CIDR + comparing to three networks.
func isRFC1918(cidr string) bool {
	for _, p := range rfc1918Prefixes {
		if strings.HasPrefix(cidr, p) {
			return true
		}
	}
	return false
}

func init() {
	compliancekit.Register(CheckNetworkOrphan, NetworkOrphan)
	compliancekit.Register(CheckNetworkRFC1918, NetworkRFC1918)
}
