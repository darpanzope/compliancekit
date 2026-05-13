package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckNoFirewall flags public-IP droplets without any firewall
// attached. This is the first cross-resource check: it traverses the
// droplet -> firewall edge populated by the collector.
var CheckNoFirewall = core.Check{
	ID:           "do-droplet-no-firewall",
	Title:        "Public-IP droplets must have at least one firewall attached",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "droplets",
	ResourceType: docol.DropletType,
	Description: "A droplet exposed to the internet via a public IPv4 address " +
		"with no firewall has every listening port reachable from anywhere. " +
		"Cloud-native compliance frameworks treat this as a critical control " +
		"gap: SOC 2 CC6.6 (logical access controls), CIS Controls v8 4.4 " +
		"(network filtering), and ISO 27001 A.8.21 all require restricted " +
		"network access for production resources.",
	Remediation: "Create a DigitalOcean Cloud Firewall and attach it: " +
		"'doctl compute firewall create --name web-fw " +
		"--inbound-rules \"protocol:tcp,ports:443,sources:address:0.0.0.0/0\" " +
		"--droplet-ids <id>'. In Terraform, use the digitalocean_firewall " +
		"resource and set droplet_ids on it.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC6.1"},
		"iso27001": {"A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"network", "exposure", "cross-resource"},
	Scanner: "firewalls.NoFirewall",
}

// NoFirewall is the CheckFunc for CheckNoFirewall. It demonstrates a
// cross-resource query against the ResourceGraph: each droplet's
// attached firewalls are read via Related rather than re-fetching.
//
// Droplets without a public IPv4 address are Skipped -- the check
// doesn't apply to private-only hosts. Droplets with at least one
// firewall Pass. Droplets with a public IP and no firewall Fail.
func NoFirewall(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	droplets := g.ByType(docol.DropletType)
	findings := make([]core.Finding, 0, len(droplets))

	for _, d := range droplets {
		f := core.Finding{
			CheckID:  CheckNoFirewall.ID,
			Severity: CheckNoFirewall.Severity,
			Resource: d.Ref(),
			Tags:     CheckNoFirewall.Tags,
		}

		if d.Attr("public_ipv4") == "" {
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("droplet %q has no public IPv4; check N/A", d.Name)
			findings = append(findings, f)
			continue
		}

		firewalls := g.Related(d, docol.EdgeFirewall)
		if len(firewalls) == 0 {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf(
				"droplet %q has public IP %s but no firewall attached",
				d.Name, d.Attr("public_ipv4"))
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf(
				"droplet %q is protected by %d firewall(s)",
				d.Name, len(firewalls))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// firewallInit registers cross-resource checks. Kept separate from the
// droplets.go init so the registration site for each check sits next
// to its definition.
func init() {
	core.Register(CheckNoFirewall.ID, NoFirewall)
}
