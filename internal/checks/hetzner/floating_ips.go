package hetzner

import (
	"context"
	"fmt"

	hetznercol "github.com/darpanzope/compliancekit/internal/collectors/hetzner"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckFloatingIPOrphan flags Floating IPs not attached to any
// server. They bill regardless of attachment status.
var CheckFloatingIPOrphan = core.Check{
	ID:           "hetzner-floating-ip-orphan",
	Title:        "Hetzner Floating IPs should be attached to a server",
	Severity:     core.SeverityLow,
	Provider:     "hetzner",
	Service:      "floating_ips",
	ResourceType: hetznercol.FloatingIPType,
	Description: "A Hetzner Cloud Floating IP bills monthly regardless " +
		"of whether it's attached. Common shape: a server was deleted " +
		"and the IP wasn't released; it now sits forever paying a fee.",
	Remediation: "Either attach to a server ('hcloud floating-ip " +
		"assign <ip-id> <server-name>') or delete ('hcloud floating-ip " +
		"delete <ip-id>').",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"floating-ip", "hygiene", "cost"},
	Scanner: "floating_ips.Orphan",
}

func FloatingIPOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ip := range g.ByType(hetznercol.FloatingIPType) {
		attached, _ := ip.Attributes["attached"].(bool)
		addr, _ := ip.Attributes["address"].(string)
		f := core.Finding{
			CheckID:  CheckFloatingIPOrphan.ID,
			Severity: CheckFloatingIPOrphan.Severity,
			Resource: ip.Ref(),
			Tags:     CheckFloatingIPOrphan.Tags,
		}
		if attached {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("floating IP %q (%s): attached", ip.Name, addr)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("floating IP %q (%s): orphan (unattached)", ip.Name, addr)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckFloatingIPOrphan, FloatingIPOrphan)
}
